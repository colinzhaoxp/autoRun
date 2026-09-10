"""共享测试夹具：临时配置 + 随机端口起真实服务。

刻意不 mock HTTP 层。这个服务的价值集中在"中间件顺序"和"进程生命周期"两处，
两者都只在真实的 socket 与真实的 fork 上才成立，mock 掉就等于没测。
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autorun import config, logging_setup, server  # noqa: E402
from autorun.audit import AuditLog  # noqa: E402
from autorun.executor import Executor  # noqa: E402
from autorun.monitor import GpuMonitor  # noqa: E402
from autorun.notify import EmailNotifier  # noqa: E402
from autorun.registry import Registry  # noqa: E402
from autorun.routes import AppContext  # noqa: E402
from autorun.security import IdempotencyCache, RateLimiter  # noqa: E402

TEST_KEY_ADMIN = "test-admin-key-0123456789abcdefghij"
TEST_KEY_CI = "test-ci-key-0123456789abcdefghijklmn"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def base_config(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "version": 1,
        "server": {
            "host": "127.0.0.1",
            "port": free_port(),
            "max_request_body_bytes": 4096,
            "socket_timeout_sec": 10,
            "max_worker_threads": 4,
        },
        "auth": {
            "header": "X-Auth-Key",
            "min_key_length": 16,
            "keys": [
                {
                    "id": "admin",
                    "key": TEST_KEY_ADMIN,
                    "allowed_aliases": ["*"],
                    "allow_raw": True,
                    "allow_kill": True,
                },
                {
                    "id": "ci",
                    "key": TEST_KEY_CI,
                    "allowed_aliases": ["hello"],
                    "allow_raw": False,
                    "allow_kill": False,
                },
            ],
        },
        "security": {
            "ip_whitelist": ["127.0.0.1/32"],
            "allow_raw_commands": True,
            "raw_command_denylist": ["(?i)\\brm\\s+-rf\\s+/(\\s|$)"],
        },
        "rate_limit": {"enabled": False},
        "execution": {
            "shell": "/bin/bash",
            "shell_args": ["-lc"],
            "default_cwd": str(tmp_path),
            "default_timeout_sec": 30,
            "max_timeout_sec": 60,
            "max_concurrent_jobs": 5,
        },
        "commands": {
            "hello": {"argv": ["/bin/echo", "hello"], "mode": "sync", "timeout_sec": 10},
            "rollback": {
                "shell": "/bin/echo rolling back to {tag}",
                "params": {
                    "tag": {
                        "required": True,
                        "pattern": r"^v[0-9]+\.[0-9]+\.[0-9]+$",
                        "max_length": 32,
                    }
                },
                "mode": "sync",
                "timeout_sec": 10,
            },
            "loose": {
                # pattern 刻意宽松：用来验证即使允许 shell 敏感字符，
                # shlex.quote 也能保证它作为单个参数传递而不被解释。
                "shell": "/bin/echo {msg}",
                "params": {"msg": {"required": True, "pattern": "^[ -~]+$", "max_length": 64}},
                "mode": "sync",
                "timeout_sec": 10,
            },
            "slow": {"shell": "sleep 60", "singleton": True, "timeout_sec": 60},
        },
        "paths": {
            "pid_file": str(tmp_path / "run/autorun.pid"),
            "state_dir": str(tmp_path / "state"),
            "job_log_dir": str(tmp_path / "logs/jobs"),
        },
        "logging": {
            "level": "DEBUG",
            "audit_file": str(tmp_path / "logs/audit.jsonl"),
            "service_file": str(tmp_path / "logs/service.log"),
            "redact_patterns": ["(?i)(password|token|secret)\\s*=\\s*\\S+"],
        },
        "registry": {"retain_finished_hours": 72, "max_records": 100},
    }
    for section, values in overrides.items():
        if isinstance(values, dict) and isinstance(cfg.get(section), dict):
            cfg[section].update(values)
        else:
            cfg[section] = values
    return cfg


def write_config(tmp_path: Path, data: dict[str, Any]) -> Path:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    os.chmod(path, 0o600)  # 权限过宽时 config.load 会拒绝
    return path


@pytest.fixture
def make_config(tmp_path: Path):
    def _make(**overrides: Any) -> config.Config:
        return config.load(write_config(tmp_path, base_config(tmp_path, **overrides)))

    return _make


@pytest.fixture
def cfg(make_config) -> config.Config:
    return make_config()


@pytest.fixture
def ctx(cfg: config.Config):
    logging_setup.setup(cfg.logging, foreground=False)
    audit = AuditLog(cfg.logging)
    registry = Registry(cfg.paths.state_dir, cfg.registry)
    executor = Executor(cfg, registry, audit)
    executor.start_monitor()
    notifier = EmailNotifier(cfg.smtp) if cfg.smtp is not None else None
    gpu_monitor = GpuMonitor(cfg, executor, audit, notifier)
    # 不调用 start()：API 测试通过注入快照读取，无需真实采样线程与真实 GPU。
    context = AppContext(
        config=cfg,
        registry=registry,
        executor=executor,
        audit=audit,
        rate_limiter=RateLimiter(cfg),
        idempotency=IdempotencyCache(),
        gpu_monitor=gpu_monitor,
    )
    yield context
    gpu_monitor.stop()
    executor.stop_monitor()
    for rec in registry.running():
        import signal as _sig

        from autorun import procutil

        procutil.signal_process_group(rec.pgid, _sig.SIGKILL)
    registry.close()


class Client:
    """极简 HTTP 客户端。返回 (状态码, 解析后的 JSON, 响应头)。"""

    def __init__(self, base_url: str) -> None:
        self.base = base_url

    def call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        key: str | None = TEST_KEY_ADMIN,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        data = raw_body if raw_body is not None else (
            json.dumps(body).encode() if body is not None else None
        )
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if key:
            req.add_header("X-Auth-Key", key)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read() or b"{}"), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                parsed = json.loads(payload or b"{}")
            except json.JSONDecodeError:
                parsed = {"raw": payload.decode("utf-8", "replace")}
            return exc.code, parsed, dict(exc.headers)

    def get(self, path: str, **kw: Any):
        return self.call("GET", path, **kw)

    def post(self, path: str, body: dict[str, Any] | None = None, **kw: Any):
        return self.call("POST", path, body=body, **kw)


@pytest.fixture
def client(ctx: AppContext):
    httpd = server.create_server(ctx)
    stop = threading.Event()
    thread = threading.Thread(target=server.serve_forever, args=(httpd, stop), daemon=True)
    thread.start()
    host, port = ctx.cfg.server.host, ctx.cfg.server.port
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.05)
    yield Client(f"http://{host}:{port}")
    stop.set()
    thread.join(timeout=5)


def read_audit(cfg: config.Config) -> list[dict[str, Any]]:
    path = Path(cfg.logging.audit_file)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def wait_until(pred, timeout: float = 20.0, interval: float = 0.05) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(interval)
    return False
