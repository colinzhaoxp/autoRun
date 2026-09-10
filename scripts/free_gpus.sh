#!/usr/bin/env bash
# Free specific GPUs: kill every process in this container that is actually
# using the given GPU indices, gracefully first, then by force.
#
#   CUDA_VISIBLE_DEVICES=2,3 bash infer/scripts/free_gpus.sh
#   bash infer/scripts/free_gpus.sh 2 3          # same thing, positionally
#   bash infer/scripts/free_gpus.sh ALL
#
# How a process is attributed to a GPU: we grep /proc/<pid>/maps for
# /dev/nvidia<N>. That is the only reliable signal available in here --
#   * nvidia-smi reports HOST pids (we are in a container; they are invisible
#     in /proc and show up as [Not Found]), so it cannot name the culprit;
#   * /proc/<pid>/fd is useless because every CUDA process *opens* all
#     /dev/nvidia* during NVML enumeration, regardless of which it uses;
#   * $CUDA_VISIBLE_DEVICES is missing on vLLM's `VLLM::EngineCore` children
#     (spawned, env stripped) and is lost entirely once they are orphaned.
# mmap'd device nodes, by contrast, are exactly the GPUs the process holds
# memory on -- verified 2026-08-25 against CUDA_VISIBLE_DEVICES of every live
# replica, and against orphaned EngineCore children with no live parent.
#
# Escalation order matters: SIGKILL on a vLLM parent is what orphans the
# EngineCore child and leaks its GPU memory in the first place, so TERM first
# and only KILL what refuses to leave.
set -uo pipefail

GRACE="${GRACE:-30}"       # seconds to wait for each SIGTERM stage
DRY_RUN="${DRY_RUN:-0}"    # 1 = list victims, kill nothing
YES="${YES:-0}"            # 1 = skip the countdown before killing

# Targets: positional args win over $CUDA_VISIBLE_DEVICES.
if [ "$#" -gt 0 ]; then
    spec="$*"
else
    spec="${CUDA_VISIBLE_DEVICES:-}"
fi
spec="${spec//,/ }"
if [ -z "${spec// /}" ]; then
    echo "usage: [CUDA_VISIBLE_DEVICES=0,1] $0 [gpu ...|ALL]" >&2
    exit 2
fi

if [[ "${spec}" =~ ^[[:space:]]*(ALL|all)[[:space:]]*$ ]]; then
    mapfile -t targets < <(nvidia-smi --query-gpu=index --format=csv,noheader)
else
    read -r -a targets <<<"${spec}"
fi
for t in "${targets[@]}"; do
    [[ "${t}" =~ ^[0-9]+$ ]] || { echo "bad gpu index: ${t}" >&2; exit 2; }
done
echo "[free-gpus] target GPUs (nvidia-smi index): ${targets[*]}"
SELF_PGID=$(ps -o pgid= -p $$ | tr -d ' ')

# The GPU index you type is an nvidia-smi index; what shows up in
# /proc/<pid>/maps is /dev/nvidia<device minor>. They happen to be equal on
# this node, but that is not guaranteed in general (nvidia-smi orders by PCI
# bus id, minors are assigned by the driver), and killing the wrong GPU's
# processes is not a mistake worth risking. Resolve index -> UUID -> minor via
# /proc/driver/nvidia/gpus/<busid>/information, which carries both.
declare -A MINOR2IDX=()
minors=()
for t in "${targets[@]}"; do
    uuid=$(nvidia-smi -i "${t}" --query-gpu=uuid --format=csv,noheader 2>/dev/null)
    minor=""
    if [ -n "${uuid}" ]; then
        for info in /proc/driver/nvidia/gpus/*/information; do
            [ -r "${info}" ] || continue
            grep -qF "${uuid}" "${info}" || continue
            minor=$(sed -n 's/^Device Minor:[[:space:]]*//p' "${info}" | tr -d ' ')
            break
        done
    fi
    if [ -z "${minor}" ]; then
        echo "[free-gpus] WARNING: cannot resolve device minor for GPU ${t}, assuming /dev/nvidia${t}" >&2
        minor="${t}"
    fi
    [ "${minor}" != "${t}" ] && echo "[free-gpus] GPU ${t} -> /dev/nvidia${minor}"
    minors+=("${minor}")
    MINOR2IDX["${minor}"]="${t}"
done

# gpus_of <pid> -> space-separated device minors the process has mmap'd
gpus_of() {
    grep -o '/dev/nvidia[0-9][0-9]*' "/proc/$1/maps" 2>/dev/null \
        | sed 's#/dev/nvidia##' | sort -un | tr '\n' ' '
}

is_target() {
    local g t
    for g in $1; do
        for t in "${minors[@]}"; do
            [ "${g}" = "${t}" ] && return 0
        done
    done
    return 1
}

# Skip our own process group: pgrep/scan would otherwise see the script, the
# shell that started it, and every command substitution it forks.
skip_pid() {
    [ "$1" = "$$" ] && return 0
    [ "$(ps -o pgid= -p "$1" 2>/dev/null | tr -d ' ')" = "${SELF_PGID}" ]
}

show() {
    local pid
    for pid in "$@"; do
        printf '  dev[%s] ' "${PID_GPUS[${pid}]:-$(gpus_of "${pid}")}"
        ps -p "${pid}" -o pid=,etime=,args= 2>/dev/null | cut -c1-120
    done
}

# Poll until every pid in the named array is gone, or GRACE expires.
term_and_wait() {
    local -n _pids=$1
    local sig=$2 waited=0 alive pid
    [ "${#_pids[@]}" -eq 0 ] && return 0
    echo "[free-gpus] SIG${sig} -> ${_pids[*]}"
    kill "-${sig}" "${_pids[@]}" 2>/dev/null
    while [ "${waited}" -lt "${GRACE}" ]; do
        alive=()
        for pid in "${_pids[@]}"; do
            kill -0 "${pid}" 2>/dev/null && alive+=("${pid}")
        done
        [ "${#alive[@]}" -eq 0 ] && { echo "[free-gpus] gone after ${waited}s"; return 0; }
        sleep 1
        waited=$((waited + 1))
    done
    echo "[free-gpus] still alive after ${GRACE}s: ${alive[*]}"
    return 1
}

gpu_mem() {
    echo "[free-gpus] memory.used (${1}):"
    nvidia-smi --query-gpu=index,memory.used --format=csv,noheader | sed 's/^/    /'
}
# scan_targets -> pids currently holding any target GPU
scan_targets() {
    local d pid
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        skip_pid "${pid}" && continue
        is_target "$(gpus_of "${pid}")" && echo "${pid}"
    done
}

declare -A PID_GPUS=()
victims=()
for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    skip_pid "${pid}" && continue
    g=$(gpus_of "${pid}")
    [ -z "${g// /}" ] && continue
    PID_GPUS["${pid}"]="${g% }"
    is_target "${g}" && victims+=("${pid}")
done

if [ "${#victims[@]}" -eq 0 ]; then
    echo "[free-gpus] no container process is using GPU ${targets[*]}"
    [ "${#PID_GPUS[@]}" -gt 0 ] && { echo "[free-gpus] other GPU users:"; show "${!PID_GPUS[@]}"; }
    gpu_mem "current"
    echo "[free-gpus] note: memory still shown as used with no local process means"
    echo "            the owner lives outside this container -- nothing we can kill."
    exit 0
fi

echo "[free-gpus] ${#victims[@]} process(es) hold the target GPUs:"
show "${victims[@]}"

# A victim may be one replica of a multi-GPU launcher. serve_summary_model_v2_multi.sh
# reacts to any replica exiting by killing the rest (`wait -n` then kill), so
# targeting a subset of its GPUs takes down its siblings on untargeted GPUs too.
# Warn instead of silently doing collateral damage.
ancestors_of() {
    local p=$1 up
    while :; do
        up=$(ps -o ppid= -p "${p}" 2>/dev/null | tr -d ' ')
        { [ -z "${up}" ] || [ "${up}" -le 1 ]; } && break
        echo "${up}"
        p=${up}
    done
}
launchers=()
for pid in "${victims[@]}"; do
    for anc in $(ancestors_of "${pid}"); do
        # Only a shell *running a serve_*.sh script* counts. Matching the bare
        # string anywhere in argv would also hit `bash -c '...serve_x.sh...'`
        # wrappers (IDE/agent shells), and TERMing those is not the intent.
        [[ "$(ps -o args= -p "${anc}" 2>/dev/null)" \
            =~ ^([^[:space:]]*/)?(ba|da|z|k)?sh[[:space:]]+(-[^c[:space:]]+[[:space:]]+)*[^[:space:]]*serve_[^[:space:]]*\.sh ]] \
            && launchers+=("${anc}")
    done
done
mapfile -t launchers < <(printf '%s\n' "${launchers[@]+"${launchers[@]}"}" | grep -E '^[0-9]+$' | sort -un)
for L in "${launchers[@]+"${launchers[@]}"}"; do
    collateral=()
    for pid in "${!PID_GPUS[@]}"; do
        is_target "${PID_GPUS[${pid}]}" && continue
        for anc in $(ancestors_of "${pid}"); do
            [ "${anc}" = "${L}" ] && collateral+=("${pid}")
        done
    done
    echo "[free-gpus] launcher ${L}: $(ps -o args= -p "${L}" 2>/dev/null | cut -c1-80)"
    if [ "${#collateral[@]}" -gt 0 ]; then
        echo "[free-gpus] WARNING: it also drives these processes on NON-target GPUs,"
        echo "            and it stops every replica when one exits -- they will die too:"
        show "${collateral[@]}"
    fi
done

gpu_mem "before"
if [ "${DRY_RUN}" = "1" ]; then
    echo "[free-gpus] DRY_RUN=1, nothing killed"
    exit 0
fi
if [ "${YES}" != "1" ]; then
    echo -n "[free-gpus] killing in 5s, Ctrl-C to abort "
    for _ in 1 2 3 4 5; do sleep 1; echo -n .; done
    echo
fi

# Stage 1: TERM the launchers -- serve_summary_model_v2_multi.sh traps TERM and
# forwards it to its replicas, the one path where vLLM shuts EngineCore down itself.
if [ "${#launchers[@]}" -gt 0 ]; then
    term_and_wait launchers TERM || true
fi

# Stage 2: TERM whatever still holds the target GPUs (single-replica launches,
# bare python runs, anything with no launcher above it).
mapfile -t victims < <(scan_targets)
term_and_wait victims TERM || true

# Stage 3: force. Orphaned EngineCore children usually land here.
mapfile -t leftovers < <(scan_targets)
if [ "${#leftovers[@]}" -gt 0 ]; then
    echo "[free-gpus] escalating to SIGKILL:"
    show "${leftovers[@]}"
    term_and_wait leftovers KILL || true
fi

sleep 3
gpu_mem "after"
mapfile -t final < <(scan_targets)
if [ "${#final[@]}" -gt 0 ]; then
    echo "[free-gpus] WARNING: survived SIGKILL (likely stuck in the driver):"
    show "${final[@]}"
    exit 1
fi
echo "[free-gpus] GPU ${targets[*]} free of local processes"
