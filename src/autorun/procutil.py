"""进程存活判定与 PID 复用防护。

核心问题：单靠 `os.kill(pid, 0)` 判断存活是不够的。守护进程重启后、或 registry
长期运行时，被记录的 PID 可能已经退出并被系统复用给一个完全无关的进程。此时按
PID 发信号就是在赌运气。

解法：把 PID 和该进程的**启动时刻**一起记录下来。两者同时匹配才认为是同一个进程。
启动时刻取自 `/proc/<pid>/stat` 的第 22 个字段（starttime，单位为时钟 tick，
自系统启动起算），它对某个 PID 的某一次生命周期是唯一的。
"""

from __future__ import annotations

import os
import signal

# 每秒的时钟 tick 数，用于把 starttime 从 tick 换算成秒。本机为 100。
CLK_TCK = os.sysconf("SC_CLK_TCK")

_STARTTIME_INDEX_AFTER_COMM = 19
"""按最后一个 `") "` 切分后，starttime 在余下字段中的 0-based 下标。

/proc/<pid>/stat 的字段编号：1=pid, 2=comm, 3=state, ..., 22=starttime。
切分后余下部分从字段 3（state）开始，故 starttime 的下标为 22 - 3 = 19。
"""


def _read_stat_fields(pid: int) -> list[str] | None:
    """返回 /proc/<pid>/stat 中 comm 之后的字段列表（从 state 开始）。

    解析时按**最后一个** `") "` 切分，而不是按空格 split 或找第一个 `)`。
    因为第 2 个字段 comm 是被括号包裹的可执行文件名，它本身可能含空格和括号
    （例如 `(my prog (v2))`），按空格切分会导致后续所有字段错位。
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    except OSError:
        return None

    text = raw.decode("utf-8", errors="replace")
    idx = text.rfind(") ")
    if idx == -1:
        return None
    return text[idx + 2 :].split()


def read_starttime_ticks(pid: int) -> int | None:
    """读取进程的 starttime（tick）。进程不存在或无权限时返回 None。"""
    fields = _read_stat_fields(pid)
    if fields is None or len(fields) <= _STARTTIME_INDEX_AFTER_COMM:
        return None
    try:
        return int(fields[_STARTTIME_INDEX_AFTER_COMM])
    except ValueError:
        return None


def pid_exists(pid: int) -> bool:
    """PID 是否对应一个**仍在运行**的进程（不判断是否为我们期望的那个）。

    僵尸进程（state Z）算作已结束：它的命令早已退出，只是父进程尚未 wait 回收。
    若把僵尸当作存活，一个已经跑完的任务会永远显示 running，也永远等不到终态。
    `os.kill(pid, 0)` 对僵尸是成功的，所以必须额外查进程状态。
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # 进程存在，只是不属于当前用户。
        return True
    except OSError:
        return False

    fields = _read_stat_fields(pid)
    if fields is None:
        # /proc 读不到但 kill(0) 成功：极短的竞态窗口，保守地认为已结束。
        return False
    # Z = zombie（已退出待回收），X/x = 已死亡
    return fields[0] not in ("Z", "X", "x")



def is_same_process(pid: int, expected_starttime_ticks: int | None) -> bool:
    """判断 `pid` 是否仍是当初记录下来的那个进程。

    这是发信号前的必经检查。`expected_starttime_ticks` 为 None 时（例如老记录里
    没存这个字段）退化为只查 PID 存在性 —— 此时无法排除 PID 复用，调用方应把
    任务状态标记为 unknown 而不是贸然发信号。
    """
    if not pid_exists(pid):
        return False
    if expected_starttime_ticks is None:
        return True
    actual = read_starttime_ticks(pid)
    if actual is None:
        # PID 存在但读不到 stat（竞态：刚好在两次系统调用之间退出）。
        return False
    return actual == expected_starttime_ticks


def signal_process_group(pgid: int, sig: signal.Signals) -> bool:
    """向整个进程组发信号，回收命令派生出的整棵子进程树。

    返回 False 表示进程组已不存在。调用方须先用 `is_same_process` 确认过目标，
    否则可能杀掉复用了该 PID 的无关进程组。
    """
    if pgid <= 0:
        return False
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False
    return True


def signal_process(pid: int, sig: signal.Signals) -> bool:
    """向单个进程发信号。返回 False 表示进程已不存在或无权限。"""
    if pid <= 0:
        return False
    try:
        os.kill(pid, sig)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False
    return True


def reap_if_child(pid: int) -> int | None:
    """非阻塞回收子进程，返回其 wait status；不是我方子进程或尚未退出时返回 None。

    用于监控线程避免留下僵尸进程。跨守护进程重启继承来的任务不是本进程的子进程，
    此时 waitpid 抛 ChildProcessError，属于预期情况。
    """
    try:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return None
    except OSError:
        return None
    if waited_pid == 0:
        return None
    return status
