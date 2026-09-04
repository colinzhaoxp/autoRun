"""配置加载、${ENV} 展开、校验，最终冻结成不可变的 dataclass 树。

设计原则：**所有校验在启动时完成，运行时不再怀疑配置**。每一条校验规则都对应一个
真实的故障模式，注释里说明了它拦的是什么。热加载时先把新配置完整解析校验成一个新
对象，成功后才原子替换 —— 因此写错配置文件不会影响正在运行的服务。
"""

from __future__ import annotations

import grp
import ipaddress
import os
import pwd
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PLACEHOLDER_PATTERN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


# --- 数据结构 -------------------------------------------------------------


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8770
    max_request_body_bytes: int = 65536
    socket_timeout_sec: float = 15.0
    max_worker_threads: int = 16
    shutdown_grace_sec: float = 10.0
    kill_jobs_on_shutdown: bool = False


@dataclass(frozen=True)
class TLSConfig:
    enabled: bool = False
    cert_file: str | None = None
    key_file: str | None = None
    client_ca_file: str | None = None


@dataclass(frozen=True)
class KeyConfig:
    id: str
    key: str
    allowed_aliases: tuple[str, ...] = ()
    allow_raw: bool = False
    allow_kill: bool = False
    allowed_ips: tuple[IPNetwork, ...] = ()

    def may_run(self, alias: str) -> bool:
        return "*" in self.allowed_aliases or alias in self.allowed_aliases

    def ip_allowed(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """按 key 的额外 IP 收窄。未配置时不额外限制（全局白名单已先行生效）。"""
        if not self.allowed_ips:
            return True
        return any(addr in net for net in self.allowed_ips)


@dataclass(frozen=True)
class AuthConfig:
    header: str = "X-Auth-Key"
    min_key_length: int = 32
    keys: tuple[KeyConfig, ...] = ()


@dataclass(frozen=True)
class SecurityConfig:
    ip_whitelist: tuple[IPNetwork, ...] = ()
    trust_proxy: bool = False
    trusted_proxies: tuple[IPNetwork, ...] = ()
    allow_raw_commands: bool = False
    raw_command_denylist: tuple[re.Pattern[str], ...] = ()
    allow_kill_untracked_pids: bool = False
    health_requires_auth: bool = False


@dataclass(frozen=True)
class RateLimitConfig:
    enabled: bool = True
    requests_per_minute: int = 60
    burst: int = 20
    per_key: bool = True


@dataclass(frozen=True)
class RunAs:
    user: str | None = None
    group: str | None = None

    @property
    def active(self) -> bool:
        return self.user is not None or self.group is not None


@dataclass(frozen=True)
class ExecutionConfig:
    shell: str = "/bin/bash"
    shell_args: tuple[str, ...] = ("-lc",)
    default_cwd: str = "/"
    default_timeout_sec: int = 900
    max_timeout_sec: int = 7200
    max_concurrent_jobs: int = 10
    max_output_bytes: int = 52428800
    on_output_limit: str = "kill"
    env_passthrough: tuple[str, ...] = ("PATH", "LANG", "HOME")
    env_extra: dict[str, str] = field(default_factory=dict)
    run_as: RunAs = field(default_factory=RunAs)


@dataclass(frozen=True)
class ParamSpec:
    name: str
    required: bool = True
    pattern: re.Pattern[str] = field(default=re.compile(r"^$"))
    max_length: int = 256
    default: str | None = None


@dataclass(frozen=True)
class CommandSpec:
    """一个预定义命令别名。

    `shell` 与 `argv` 必须恰好有一个非空 —— 这在校验阶段强制。argv 形式完全不经过
    shell，是最安全的；shell 形式支持管道和 `&&` 等语法，参数经正则白名单校验后
    再用 shlex.quote 代入。
    """

    name: str
    description: str = ""
    shell: str | None = None
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    timeout_sec: int | None = None
    singleton: bool = False
    mode: str = "background"
    params: dict[str, ParamSpec] = field(default_factory=dict)
    run_as: RunAs | None = None

    @property
    def uses_shell(self) -> bool:
        return self.shell is not None


@dataclass(frozen=True)
class PathsConfig:
    pid_file: Path = Path("runtime/autorun.pid")
    state_dir: Path = Path("runtime/state")
    job_log_dir: Path = Path("runtime/logs/jobs")


@dataclass(frozen=True)
class RotationConfig:
    strategy: str = "size"
    max_bytes: int = 52428800
    when: str = "midnight"
    backup_count: int = 14


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    audit_file: Path = Path("runtime/logs/audit.jsonl")
    service_file: Path = Path("runtime/logs/service.log")
    rotation: RotationConfig = field(default_factory=RotationConfig)
    redact_patterns: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class RegistryConfig:
    retain_finished_hours: int = 72
    max_records: int = 2000
    render_text_view: bool = True


@dataclass(frozen=True)
class Config:
    source_path: Path
    base_dir: Path
    server: ServerConfig
    tls: TLSConfig
    auth: AuthConfig
    security: SecurityConfig
    rate_limit: RateLimitConfig
    execution: ExecutionConfig
    commands: dict[str, CommandSpec]
    paths: PathsConfig
    logging: LoggingConfig
    registry: RegistryConfig
    warnings: tuple[str, ...] = ()

    def find_key(self, presented: str) -> KeyConfig | None:
        """恒定时间比对所有已配置密钥。见 security.py 中的说明。"""
        import hmac

        matched: KeyConfig | None = None
        for kc in self.auth.keys:
            if hmac.compare_digest(kc.key, presented):
                matched = kc
        return matched


# --- 解析辅助 -------------------------------------------------------------


def _expand_env(value: str, where: str) -> str:
    """展开 ${VAR}。未定义的变量直接报错而不是留下空串。

    拦的故障：密钥环境变量忘记 export 时，静默变成空串会让认证形同虚设。
    """

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        got = os.environ.get(name)
        if got is None:
            raise ConfigError(
                f"{where}: 环境变量 ${{{name}}} 未定义。"
                f"请在项目根目录的 .env 中添加 {name}=...（参考 .env.example），"
                f"或直接 export {name}=..."
            )
        return got

    return _ENV_PATTERN.sub(repl, value)


def _expand_tree(node: Any, where: str = "") -> Any:
    if isinstance(node, str):
        return _expand_env(node, where or "config")
    if isinstance(node, dict):
        return {k: _expand_tree(v, f"{where}.{k}" if where else str(k)) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_tree(v, f"{where}[{i}]") for i, v in enumerate(node)]
    return node


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    got = data.get(name) or {}
    if not isinstance(got, dict):
        raise ConfigError(f"配置段 `{name}` 必须是映射，实际是 {type(got).__name__}")
    return got


def _networks(values: Any, where: str) -> tuple[IPNetwork, ...]:
    """解析 CIDR 列表。任何一条解析失败都中止启动。

    拦的故障：静默跳过一条写错的白名单条目，会让运维以为某个网段被允许了，
    实际上它被丢掉了 —— 或者更糟，以为某个限制生效了，实际没生效。
    """
    if values is None:
        return ()
    if not isinstance(values, list):
        raise ConfigError(f"{where} 必须是列表")
    out: list[IPNetwork] = []
    for item in values:
        try:
            out.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError as exc:
            raise ConfigError(f"{where}: 无法解析网段 {item!r}: {exc}") from exc
    return tuple(out)


def _regexes(values: Any, where: str) -> tuple[re.Pattern[str], ...]:
    if values is None:
        return ()
    if not isinstance(values, list):
        raise ConfigError(f"{where} 必须是列表")
    out: list[re.Pattern[str]] = []
    for item in values:
        try:
            out.append(re.compile(str(item)))
        except re.error as exc:
            raise ConfigError(f"{where}: 无效正则 {item!r}: {exc}") from exc
    return tuple(out)


def _resolve(base: Path, value: Any, default: str) -> Path:
    """相对路径按配置文件所在目录解析，避免受进程 cwd 影响。"""
    raw = str(value) if value is not None else default
    p = Path(raw).expanduser()
    return p if p.is_absolute() else (base / p)


def _run_as(data: Any, where: str) -> RunAs:
    if not data:
        return RunAs()
    if not isinstance(data, dict):
        raise ConfigError(f"{where} 必须是映射")
    user = data.get("user")
    group = data.get("group")
    # 启动时就确认用户/组存在，而不是等到第一次执行命令才失败。
    if user is not None:
        try:
            pwd.getpwnam(str(user))
        except KeyError as exc:
            raise ConfigError(f"{where}.user: 系统中不存在用户 {user!r}") from exc
    if group is not None:
        try:
            grp.getgrnam(str(group))
        except KeyError as exc:
            raise ConfigError(f"{where}.group: 系统中不存在用户组 {group!r}") from exc
    return RunAs(user=str(user) if user else None, group=str(group) if group else None)


def _parse_params(raw: Any, where: str) -> dict[str, ParamSpec]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}.params 必须是映射")
    out: dict[str, ParamSpec] = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"{where}.params.{name} 必须是映射")
        # 没有 pattern 的参数直接拒绝。这是注入防线的地基：不允许出现
        # "先上线、以后再补校验" 的参数，否则任意值会被代入命令。
        if "pattern" not in spec:
            raise ConfigError(
                f"{where}.params.{name}: 必须声明 pattern（无正则白名单的参数不允许使用）"
            )
        raw_pattern = str(spec["pattern"])
        # 空 pattern 用 fullmatch 匹配时只接受空字符串，任何非空输入都会被拒 ——
        # 而写下 `pattern: ""` 的人几乎总是想表达"不限制"。语义正好相反，
        # 且报错信息（"不满足格式 ()"）毫无提示性，所以在启动时就拦住。
        if not raw_pattern:
            raise ConfigError(
                f"{where}.params.{name}.pattern 为空。空正则只匹配空字符串，"
                f'任何输入都会被拒绝。若要接受任意单行文本请写 pattern: "^.*$"，'
                f"但更推荐收窄到实际需要的形状"
            )
        try:
            pattern = re.compile(raw_pattern)
        except re.error as exc:
            raise ConfigError(f"{where}.params.{name}.pattern 无效: {exc}") from exc
        max_length = int(spec.get("max_length", 256))
        if max_length <= 0:
            raise ConfigError(f"{where}.params.{name}.max_length 必须为正数")
        default = spec.get("default")
        required = bool(spec.get("required", True))
        if default is not None:
            # 默认值同样必须通过自己的校验规则，否则等于开了个后门。
            if not pattern.fullmatch(str(default)):
                raise ConfigError(f"{where}.params.{name}.default 不满足自身 pattern")
            required = False
        out[name] = ParamSpec(
            name=str(name),
            required=required,
            pattern=pattern,
            max_length=max_length,
            default=str(default) if default is not None else None,
        )
    return out


def _parse_command(name: str, raw: Any, base: Path) -> CommandSpec:
    where = f"commands.{name}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} 必须是映射")

    shell_body = raw.get("shell")
    argv_raw = raw.get("argv")

    # 恰好一个。两个都给意味着意图不明（哪个生效？），都不给则无事可做。
    if (shell_body is None) == (argv_raw is None):
        raise ConfigError(f"{where}: 必须恰好指定 `shell` 或 `argv` 之一")

    argv: tuple[str, ...] = ()
    if argv_raw is not None:
        if not isinstance(argv_raw, list) or not argv_raw:
            raise ConfigError(f"{where}.argv 必须是非空列表")
        argv = tuple(str(x) for x in argv_raw)

    params = _parse_params(raw.get("params"), where)

    # 占位符与 params 声明必须双向一致。
    texts = [shell_body] if shell_body is not None else list(argv)
    used: set[str] = set()
    for text in texts:
        used.update(_PLACEHOLDER_PATTERN.findall(str(text)))

    undeclared = used - params.keys()
    if undeclared:
        # 拦的故障：命令里写了 {tag} 但忘记声明 params.tag，那么该占位符要么原样
        # 传给 shell（字面量 `{tag}`），要么被当作可自由替换的值 —— 都是错的。
        raise ConfigError(
            f"{where}: 命令中的占位符 {sorted(undeclared)} 未在 params 中声明"
        )
    unused = params.keys() - used
    if unused:
        # 拦的故障：声明了参数但命令里拼错了占位符名，导致参数被静默忽略，
        # 调用方以为自己传的值生效了，实际没有。
        raise ConfigError(f"{where}: params {sorted(unused)} 未被命令引用（占位符拼写错误？）")

    mode = str(raw.get("mode", "background"))
    if mode not in ("background", "sync"):
        raise ConfigError(f"{where}.mode 只能是 background 或 sync")

    timeout = raw.get("timeout_sec")
    if timeout is not None:
        timeout = int(timeout)
        if timeout <= 0:
            raise ConfigError(f"{where}.timeout_sec 必须为正数")

    cwd = raw.get("cwd")
    return CommandSpec(
        name=name,
        description=str(raw.get("description", "")),
        shell=str(shell_body) if shell_body is not None else None,
        argv=argv,
        cwd=str(_resolve(base, cwd, ".")) if cwd is not None else None,
        timeout_sec=timeout,
        singleton=bool(raw.get("singleton", False)),
        mode=mode,
        params=params,
        run_as=_run_as(raw.get("run_as"), f"{where}.run_as") if raw.get("run_as") else None,
    )


def _parse_keys(raw: Any, min_len: int) -> tuple[KeyConfig, ...]:
    if not raw:
        raise ConfigError("auth.keys 不能为空，否则无人可调用本服务")
    if not isinstance(raw, list):
        raise ConfigError("auth.keys 必须是列表")
    out: list[KeyConfig] = []
    seen: set[str] = set()
    for i, item in enumerate(raw):
        where = f"auth.keys[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} 必须是映射")
        kid = str(item.get("id") or "")
        if not kid:
            raise ConfigError(f"{where}.id 不能为空")
        if kid in seen:
            # 拦的故障：重复 id 会让审计日志无法区分是哪个调用方。
            raise ConfigError(f"{where}.id 重复: {kid!r}")
        seen.add(kid)
        key = str(item.get("key") or "")
        # 短密钥可被暴力破解。宁可启动失败，也不要上线一个弱密钥。
        if len(key) < min_len:
            raise ConfigError(
                f"{where}.key 长度 {len(key)} 小于 auth.min_key_length={min_len}"
            )
        aliases = item.get("allowed_aliases") or []
        if not isinstance(aliases, list):
            raise ConfigError(f"{where}.allowed_aliases 必须是列表")
        out.append(
            KeyConfig(
                id=kid,
                key=key,
                allowed_aliases=tuple(str(a) for a in aliases),
                allow_raw=bool(item.get("allow_raw", False)),
                allow_kill=bool(item.get("allow_kill", False)),
                allowed_ips=_networks(item.get("allowed_ips"), f"{where}.allowed_ips"),
            )
        )
    return tuple(out)


def load(path: str | os.PathLike[str]) -> Config:
    """加载并全量校验配置。任何问题都抛 ConfigError，不返回半成品配置。"""
    cfg_path = Path(path).expanduser().resolve()
    if not cfg_path.is_file():
        raise ConfigError(f"配置文件不存在: {cfg_path}")

    warnings: list[str] = []

    # 配置文件持有或引用密钥，group/world 可读即视为泄露风险。
    mode = cfg_path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        raise ConfigError(
            f"配置文件 {cfg_path} 权限过宽（{stat.filemode(mode)}），"
            f"它涉及密钥，请执行 chmod 600"
        )

    try:
        with cfg_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML 解析失败: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("配置文件顶层必须是映射")

    raw = _expand_tree(raw)
    base = cfg_path.parent.parent  # config/config.yaml -> 项目根

    srv_raw = _section(raw, "server")
    server = ServerConfig(
        host=str(srv_raw.get("host", "127.0.0.1")),
        port=int(srv_raw.get("port", 8770)),
        max_request_body_bytes=int(srv_raw.get("max_request_body_bytes", 65536)),
        socket_timeout_sec=float(srv_raw.get("socket_timeout_sec", 15)),
        max_worker_threads=int(srv_raw.get("max_worker_threads", 16)),
        shutdown_grace_sec=float(srv_raw.get("shutdown_grace_sec", 10)),
        kill_jobs_on_shutdown=bool(srv_raw.get("kill_jobs_on_shutdown", False)),
    )
    if not (1 <= server.port <= 65535):
        raise ConfigError(f"server.port 越界: {server.port}")
    if server.max_worker_threads < 1:
        raise ConfigError("server.max_worker_threads 必须 >= 1")

    tls_raw = _section(raw, "tls")
    tls = TLSConfig(
        enabled=bool(tls_raw.get("enabled", False)),
        cert_file=tls_raw.get("cert_file"),
        key_file=tls_raw.get("key_file"),
        client_ca_file=tls_raw.get("client_ca_file"),
    )
    if tls.enabled:
        for label, fp in (("cert_file", tls.cert_file), ("key_file", tls.key_file)):
            if not fp:
                raise ConfigError(f"tls.enabled 为真时必须提供 tls.{label}")
            if not Path(fp).is_file():
                raise ConfigError(f"tls.{label} 不存在: {fp}")
        if tls.client_ca_file and not Path(tls.client_ca_file).is_file():
            raise ConfigError(f"tls.client_ca_file 不存在: {tls.client_ca_file}")

    auth_raw = _section(raw, "auth")
    min_key_length = int(auth_raw.get("min_key_length", 32))
    auth = AuthConfig(
        header=str(auth_raw.get("header", "X-Auth-Key")),
        min_key_length=min_key_length,
        keys=_parse_keys(auth_raw.get("keys"), min_key_length),
    )

    sec_raw = _section(raw, "security")
    whitelist = _networks(sec_raw.get("ip_whitelist"), "security.ip_whitelist")
    if not whitelist:
        # fail closed：空白名单的语义如果是"全部允许"，一次误删就等于全网开放。
        raise ConfigError("security.ip_whitelist 为空 —— 服务会拒绝所有请求，请显式配置")
    security = SecurityConfig(
        ip_whitelist=whitelist,
        trust_proxy=bool(sec_raw.get("trust_proxy", False)),
        trusted_proxies=_networks(sec_raw.get("trusted_proxies"), "security.trusted_proxies"),
        allow_raw_commands=bool(sec_raw.get("allow_raw_commands", False)),
        raw_command_denylist=_regexes(
            sec_raw.get("raw_command_denylist"), "security.raw_command_denylist"
        ),
        allow_kill_untracked_pids=bool(sec_raw.get("allow_kill_untracked_pids", False)),
        health_requires_auth=bool(sec_raw.get("health_requires_auth", False)),
    )
    if security.trust_proxy and not security.trusted_proxies:
        # 无条件相信 X-Forwarded-For 等于任何人都能伪造来源 IP 绕过白名单。
        raise ConfigError("security.trust_proxy 为真时必须配置 trusted_proxies")

    rl_raw = _section(raw, "rate_limit")
    rate_limit = RateLimitConfig(
        enabled=bool(rl_raw.get("enabled", True)),
        requests_per_minute=int(rl_raw.get("requests_per_minute", 60)),
        burst=int(rl_raw.get("burst", 20)),
        per_key=bool(rl_raw.get("per_key", True)),
    )
    if rate_limit.requests_per_minute < 1 or rate_limit.burst < 1:
        raise ConfigError("rate_limit.requests_per_minute / burst 必须 >= 1")

    ex_raw = _section(raw, "execution")
    env_extra_raw = ex_raw.get("env_extra") or {}
    if not isinstance(env_extra_raw, dict):
        raise ConfigError("execution.env_extra 必须是映射")
    execution = ExecutionConfig(
        shell=str(ex_raw.get("shell", "/bin/bash")),
        shell_args=tuple(str(a) for a in (ex_raw.get("shell_args") or ["-lc"])),
        default_cwd=str(_resolve(base, ex_raw.get("default_cwd"), "/")),
        default_timeout_sec=int(ex_raw.get("default_timeout_sec", 900)),
        max_timeout_sec=int(ex_raw.get("max_timeout_sec", 7200)),
        max_concurrent_jobs=int(ex_raw.get("max_concurrent_jobs", 10)),
        max_output_bytes=int(ex_raw.get("max_output_bytes", 52428800)),
        on_output_limit=str(ex_raw.get("on_output_limit", "kill")),
        env_passthrough=tuple(
            str(v) for v in (ex_raw.get("env_passthrough") or ["PATH", "LANG", "HOME"])
        ),
        env_extra={str(k): str(v) for k, v in env_extra_raw.items()},
        run_as=_run_as(ex_raw.get("run_as"), "execution.run_as"),
    )
    if not Path(execution.shell).is_file():
        raise ConfigError(f"execution.shell 不存在: {execution.shell}")
    if execution.on_output_limit not in ("kill", "warn"):
        raise ConfigError("execution.on_output_limit 只能是 kill 或 warn")
    if execution.default_timeout_sec > execution.max_timeout_sec:
        raise ConfigError("execution.default_timeout_sec 不能大于 max_timeout_sec")
    if execution.max_concurrent_jobs < 1:
        raise ConfigError("execution.max_concurrent_jobs 必须 >= 1")

    cmd_raw = raw.get("commands") or {}
    if not isinstance(cmd_raw, dict):
        raise ConfigError("commands 必须是映射")
    commands = {str(k): _parse_command(str(k), v, base) for k, v in cmd_raw.items()}
    for spec in commands.values():
        if spec.timeout_sec and spec.timeout_sec > execution.max_timeout_sec:
            raise ConfigError(
                f"commands.{spec.name}.timeout_sec 超过 execution.max_timeout_sec"
            )

    # 别名 ACL 里引用了不存在的命令，说明配置漂移了（命令改名但 ACL 没跟上），
    # 结果是该 key 静默失去权限。启动时就报出来。
    known = set(commands)
    for kc in auth.keys:
        bad = {a for a in kc.allowed_aliases if a != "*"} - known
        if bad:
            raise ConfigError(
                f"auth.keys[{kc.id}].allowed_aliases 引用了不存在的命令: {sorted(bad)}"
            )

    p_raw = _section(raw, "paths")
    paths = PathsConfig(
        pid_file=_resolve(base, p_raw.get("pid_file"), "runtime/autorun.pid"),
        state_dir=_resolve(base, p_raw.get("state_dir"), "runtime/state"),
        job_log_dir=_resolve(base, p_raw.get("job_log_dir"), "runtime/logs/jobs"),
    )

    log_raw = _section(raw, "logging")
    rot_raw = log_raw.get("rotation") or {}
    if not isinstance(rot_raw, dict):
        raise ConfigError("logging.rotation 必须是映射")
    rotation = RotationConfig(
        strategy=str(rot_raw.get("strategy", "size")),
        max_bytes=int(rot_raw.get("max_bytes", 52428800)),
        when=str(rot_raw.get("when", "midnight")),
        backup_count=int(rot_raw.get("backup_count", 14)),
    )
    if rotation.strategy not in ("size", "time"):
        raise ConfigError("logging.rotation.strategy 只能是 size 或 time")
    level = str(log_raw.get("level", "INFO")).upper()
    if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        raise ConfigError(f"logging.level 非法: {level}")
    logging_cfg = LoggingConfig(
        level=level,
        audit_file=_resolve(base, log_raw.get("audit_file"), "runtime/logs/audit.jsonl"),
        service_file=_resolve(base, log_raw.get("service_file"), "runtime/logs/service.log"),
        rotation=rotation,
        redact_patterns=_regexes(log_raw.get("redact_patterns"), "logging.redact_patterns"),
    )

    reg_raw = _section(raw, "registry")
    registry = RegistryConfig(
        retain_finished_hours=int(reg_raw.get("retain_finished_hours", 72)),
        max_records=int(reg_raw.get("max_records", 2000)),
        render_text_view=bool(reg_raw.get("render_text_view", True)),
    )

    # --- 告警（不阻止启动，但必须让运维看见） ---
    try:
        host_addr = ipaddress.ip_address(server.host)
        loopback = host_addr.is_loopback
    except ValueError:
        loopback = server.host in ("localhost",)
    if not tls.enabled and not loopback:
        warnings.append(
            f"server.host={server.host} 且未启用 TLS：共享密钥将以明文穿越网络。"
            f"建议启用 tls 或置于 nginx/VPN 之后。"
        )
    if os.geteuid() == 0 and not execution.run_as.active:
        warnings.append(
            "服务以 root 运行且未配置 execution.run_as：所有命令都将以 root 身份执行。"
        )
    if security.allow_raw_commands:
        warnings.append(
            "security.allow_raw_commands 已开启：持有 allow_raw 密钥者可执行任意命令。"
        )

    return Config(
        source_path=cfg_path,
        base_dir=base,
        server=server,
        tls=tls,
        auth=auth,
        security=security,
        rate_limit=rate_limit,
        execution=execution,
        commands=commands,
        paths=paths,
        logging=logging_cfg,
        registry=registry,
        warnings=tuple(warnings),
    )
