"""日志基础设施：服务日志与审计日志的轮转、以及 SIGHUP 重开文件。

两条流刻意分开：
- 服务日志（`service.log`）：本服务自身的运行信息与堆栈，给排障用。
- 审计日志（`audit.jsonl`）：结构化的请求/执行流水，给追溯用，见 audit.py。

轮转由本进程内的 handler 负责。由于全局只有一个写者进程，不存在多写者轮转竞争 ——
这个性质靠"永不引入第二个写者"来维持。同时支持外部 logrotate 的 copytruncate 模式：
收到 SIGHUP 时关闭并重开所有文件句柄。
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from .config import LoggingConfig, RotationConfig

SERVICE_LOGGER = "autorun"

_managed_handlers: list[logging.Handler] = []


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def build_rotating_handler(path: Path, rotation: RotationConfig) -> logging.Handler:
    """按配置创建 size 或 time 轮转的 handler，并登记以便 SIGHUP 时重开。"""
    _ensure_parent(path)
    handler: logging.Handler
    if rotation.strategy == "time":
        handler = logging.handlers.TimedRotatingFileHandler(
            path,
            when=rotation.when,
            backupCount=rotation.backup_count,
            encoding="utf-8",
            delay=True,
        )
    else:
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=rotation.max_bytes,
            backupCount=rotation.backup_count,
            encoding="utf-8",
            delay=True,
        )
    _managed_handlers.append(handler)
    return handler


def setup(cfg: LoggingConfig, *, foreground: bool = False) -> logging.Logger:
    """初始化服务日志。foreground 为真时同时输出到 stderr，便于前台调试。"""
    logger = logging.getLogger(SERVICE_LOGGER)
    logger.setLevel(cfg.level)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(threadName)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    file_handler = build_rotating_handler(cfg.service_file, cfg.rotation)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    if foreground:
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        logger.addHandler(stream)

    return logger


def set_level(level: str) -> None:
    """SIGHUP 热加载时调整级别，无需重启。"""
    logging.getLogger(SERVICE_LOGGER).setLevel(level)


def reopen_files() -> None:
    """关闭并重开所有受管文件句柄。

    这让外部 logrotate 的 copytruncate（或 create 模式 + SIGHUP）能够生效：
    否则轮转后本进程仍持有旧 inode 的句柄，新日志会写进一个已被改名的文件。
    """
    for handler in _managed_handlers:
        if isinstance(handler, logging.handlers.BaseRotatingHandler):
            with handler.lock if handler.lock else _nullctx():
                if handler.stream:
                    handler.stream.close()
                    handler.stream = None  # type: ignore[assignment]


class _nullctx:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


def get_logger(name: str = SERVICE_LOGGER) -> logging.Logger:
    return logging.getLogger(name)
