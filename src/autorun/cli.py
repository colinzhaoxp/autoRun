"""命令行入口：start / stop / restart / status / reload / foreground / ps / kill / validate。"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import __version__, config, envfile, logging_setup, server
from .audit import AuditLog
from .daemon import PidFile, daemonize, install_signal_handlers, send_signal
from .errors import AppError, ConfigError
from .executor import Executor
from .registry import Registry, render_table
from .routes import AppContext
from .security import IdempotencyCache, RateLimiter

DEFAULT_CONFIG = "config/config.yaml"

# 由 main() 填充，供 validate 打印加载详情。
_ENV_RESULT: envfile.EnvLoadResult | None = None


def _load_env(args: argparse.Namespace) -> envfile.EnvLoadResult:
    """在解析配置之前加载 .env —— config.yaml 里的 ${VAR} 依赖它。"""
    if getattr(args, "no_env_file", False):
        return envfile.EnvLoadResult(None)
    explicit = getattr(args, "env_file", None)
    if explicit:
        return envfile.load(explicit, required=True)
    return envfile.load(envfile.default_path_for_config(args.config))



def _load(path: str) -> config.Config:
    return config.load(path)


def _build_context(cfg: config.Config, *, foreground: bool) -> AppContext:
    logging_setup.setup(cfg.logging, foreground=foreground)
    audit = AuditLog(cfg.logging)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    executor = Executor(cfg, registry, audit)
    return AppContext(
        config=cfg,
        registry=registry,
        executor=executor,
        audit=audit,
        rate_limiter=RateLimiter(cfg),
        idempotency=IdempotencyCache(),
    )


def _run_service(cfg: config.Config, *, foreground: bool) -> int:
    log = logging_setup.get_logger()
    ctx = _build_context(cfg, foreground=foreground)
    for w in cfg.warnings:
        log.warning(w)
    if _ENV_RESULT is not None and _ENV_RESULT.loaded:
        log.info("env: %s", _ENV_RESULT.summary())

    pidfile = PidFile(cfg.paths.pid_file)
    pidfile.acquire()

    # 对账必须在开始接受请求之前完成：否则新任务与上次遗留的记录混在一起，
    # 无法区分哪些是孤儿。
    ctx.executor.reconcile()
    ctx.executor.start_monitor()

    stop_event = threading.Event()

    def on_reload() -> None:
        # 先重新加载 .env，这样密钥轮换只需改文件 + reload，不必重启。
        # 只覆盖上次确实由 .env 提供的键，不会踩掉 shell 里显式指定的变量。
        if _ENV_RESULT is not None and _ENV_RESULT.loaded:
            try:
                again = envfile.load(_ENV_RESULT.path, override=set(_ENV_RESULT.applied))
                log.info("env 已重新加载: %s", again.summary())
            except ConfigError as exc:
                log.error("重新加载 env 文件失败，继续使用旧值: %s", exc)
        # 配置同样先完整解析校验成新对象，成功后才替换。写错不影响正在运行的服务。
        try:
            new_cfg = _load(str(cfg.source_path))
        except ConfigError as exc:
            log.error("配置重载失败，继续使用旧配置: %s", exc)
            ctx.audit.config_reload(result="failed", detail=str(exc))
            return
        ctx.replace_config(new_cfg)
        logging_setup.set_level(new_cfg.logging.level)
        logging_setup.reopen_files()
        for w in new_cfg.warnings:
            log.warning(w)
        log.info("配置已重载")
        ctx.audit.config_reload(result="ok")

    install_signal_handlers(stop_event.set, on_reload)

    try:
        httpd = server.create_server(ctx)
    except ConfigError as exc:
        pidfile.release()
        print(f"启动失败: {exc}", file=sys.stderr)
        return 1

    scheme = "https" if cfg.tls.enabled else "http"
    log.info(
        "autoRun %s 已启动 pid=%s 监听 %s://%s:%s",
        __version__,
        os.getpid(),
        scheme,
        cfg.server.host,
        cfg.server.port,
    )
    if foreground:
        print(f"autoRun {__version__} 监听 {scheme}://{cfg.server.host}:{cfg.server.port}")
        print(f"审计日志: {cfg.logging.audit_file}")
        print(f"任务跟踪: {cfg.paths.state_dir / 'processes.txt'}")
        print("Ctrl-C 退出")

    try:
        server.serve_forever(httpd, stop_event)
    finally:
        ctx.executor.shutdown()
        ctx.registry.flush()
        ctx.registry.close()
        pidfile.release()
        log.info("已退出")
    return 0


# --- 子命令 ---------------------------------------------------------------


def cmd_validate(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    print(f"配置校验通过: {cfg.source_path}")
    if _ENV_RESULT is not None:
        print(f"  env 文件  : {_ENV_RESULT.summary()}")
    print(f"  监听      : {'https' if cfg.tls.enabled else 'http'}://{cfg.server.host}:{cfg.server.port}")
    print(f"  密钥      : {', '.join(k.id for k in cfg.auth.keys)}")
    print(f"  IP 白名单 : {', '.join(str(n) for n in cfg.security.ip_whitelist)}")
    print(f"  命令别名  : {', '.join(cfg.commands) or '(无)'}")
    print(f"  裸命令    : {'开启' if cfg.security.allow_raw_commands else '关闭'}")
    print(f"  状态目录  : {cfg.paths.state_dir}")
    for w in cfg.warnings:
        print(f"  [警告] {w}")
    return 0


def cmd_foreground(args: argparse.Namespace) -> int:
    return _run_service(_load(args.config), foreground=True)


def cmd_start(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    pidfile = PidFile(cfg.paths.pid_file)
    if pidfile.is_locked():
        print(f"服务已在运行（pid={pidfile.read_pid()}）", file=sys.stderr)
        return 1
    print(f"启动中，日志见 {cfg.logging.service_file}")
    daemonize(cfg.base_dir)
    return _run_service(cfg, foreground=False)


def cmd_stop(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    pidfile = PidFile(cfg.paths.pid_file)
    pid = pidfile.read_pid()
    if pid is None or not pidfile.is_locked():
        print("服务未在运行")
        return 0
    if not send_signal(pid, signal.SIGTERM):
        print(f"pid {pid} 已不存在", file=sys.stderr)
        return 1
    deadline = time.monotonic() + cfg.server.shutdown_grace_sec
    while time.monotonic() < deadline:
        if not pidfile.is_locked():
            print(f"已停止（pid {pid}）")
            return 0
        time.sleep(0.2)
    print(f"等待 {cfg.server.shutdown_grace_sec}s 后仍未退出，请检查 {cfg.logging.service_file}", file=sys.stderr)
    return 1


def cmd_restart(args: argparse.Namespace) -> int:
    cmd_stop(args)
    return cmd_start(args)


def cmd_reload(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    # 先在本地校验一遍：直接给服务发 SIGHUP 的话，配置写错时只能去翻日志才知道。
    print("本地校验通过，发送 SIGHUP")
    pid = PidFile(cfg.paths.pid_file).read_pid()
    if pid is None:
        print("服务未在运行", file=sys.stderr)
        return 1
    return 0 if send_signal(pid, signal.SIGHUP) else 1


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    pidfile = PidFile(cfg.paths.pid_file)
    running = pidfile.is_locked()
    pid = pidfile.read_pid()
    print(f"服务状态: {'运行中' if running else '未运行'}" + (f"  pid={pid}" if running else ""))
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    try:
        jobs = registry.all()
        print(f"任务: 共 {len(jobs)}，运行中 {sum(1 for j in jobs if j.is_running)}")
    finally:
        registry.close()
    return 0 if running else 1


def cmd_ps(args: argparse.Namespace) -> int:
    cfg = _load(args.config)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    try:
        jobs = registry.all()
        if args.running:
            jobs = [j for j in jobs if j.is_running]
        if args.json:
            print(json.dumps([j.to_dict() for j in jobs], ensure_ascii=False, indent=2))
        else:
            print(render_table(jobs))
    finally:
        registry.close()
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    """本地终止任务。

    不经过 HTTP，因此不需要密钥 —— 但它要求本机 shell 访问权限，那已经比密钥更高的
    权限了。用于服务本身失联时的应急处置。
    """
    cfg = _load(args.config)
    logging_setup.setup(cfg.logging, foreground=False)
    audit = AuditLog(cfg.logging)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    executor = Executor(cfg, registry, audit)
    try:
        sig = signal.SIGKILL if args.force else signal.SIGTERM
        result = executor.kill(args.job_id, sig=sig, actor="cli", request_id="cli")
        print(json.dumps(result, ensure_ascii=False))
    finally:
        registry.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="autorun", description="autoRun 远程命令执行服务")
    p.add_argument("--version", action="version", version=f"autoRun {__version__}")
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG, help=f"配置文件路径（默认 {DEFAULT_CONFIG}）")
    p.add_argument(
        "--env-file",
        help="密钥等环境变量文件（默认自动读取项目根目录的 .env，不存在则跳过）",
    )
    p.add_argument(
        "--no-env-file",
        action="store_true",
        help="不读取 .env，只使用当前环境变量",
    )
    sub = p.add_subparsers(dest="command", required=True)

    for name, fn, help_text in (
        ("start", cmd_start, "后台启动服务"),
        ("stop", cmd_stop, "停止服务"),
        ("restart", cmd_restart, "重启服务"),
        ("reload", cmd_reload, "重载配置（SIGHUP）"),
        ("status", cmd_status, "查看服务状态"),
        ("foreground", cmd_foreground, "前台运行（调试用）"),
        ("validate", cmd_validate, "只校验配置，不启动"),
    ):
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=fn)

    ps = sub.add_parser("ps", help="列出任务及其 PID")
    ps.add_argument("--running", action="store_true", help="只显示运行中的任务")
    ps.add_argument("--json", action="store_true", help="输出 JSON")
    ps.set_defaults(func=cmd_ps)

    kill = sub.add_parser("kill", help="终止指定任务")
    kill.add_argument("job_id")
    kill.add_argument("-9", "--force", action="store_true", help="直接发送 SIGKILL")
    kill.set_defaults(func=cmd_kill)

    return p


def main(argv: list[str] | None = None) -> int:
    global _ENV_RESULT
    args = build_parser().parse_args(argv)
    # 相对配置路径按 cwd 解析，但要给出清晰提示而不是 FileNotFoundError。
    if not Path(args.config).is_file():
        print(
            f"找不到配置文件 {args.config}\n"
            f"提示: cp config/config.example.yaml config/config.yaml && chmod 600 config/config.yaml",
            file=sys.stderr,
        )
        return 1
    try:
        # 必须先于任何配置解析：config.yaml 里的 ${AUTORUN_KEY_*} 依赖这些变量。
        _ENV_RESULT = _load_env(args)
        return args.func(args)
    except AppError as exc:
        print(f"错误: {exc.message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
