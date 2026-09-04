"""守护化与 PID 文件管理。

生产环境推荐用 systemd（见 deploy/autorun.service），它比自建双 fork 更可靠：进程
监督、崩溃重启、日志接管都是现成的。这里的双 fork 路径是给没有 systemd 的环境兜底。

PID 文件用 flock 而不是"写文件 + 检查 PID 是否存在"：后者在 PID 被复用时会误判成
"服务已在运行"，而 flock 由内核维护，进程一死锁自动释放，不存在这个问题。
"""

from __future__ import annotations

import errno
import fcntl
import os
import signal
import sys
from pathlib import Path

from .errors import ConfigError
from .logging_setup import get_logger

log = get_logger("autorun.daemon")


class PidFile:
    """基于 flock 的单实例守卫。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fd: int | None = None

    def acquire(self) -> None:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                existing = self.read_pid()
                raise ConfigError(
                    f"服务已在运行（pid={existing}，锁文件 {self.path}）。"
                    f"如需重启请先执行 `autorun stop`。"
                ) from exc
            raise
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        os.fsync(fd)
        self._fd = fd

    def read_pid(self) -> int | None:
        try:
            text = self.path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None
        try:
            self.path.unlink()
        except OSError:
            pass

    def is_locked(self) -> bool:
        """在不干扰持有者的前提下探测锁是否被占用。"""
        try:
            fd = os.open(self.path, os.O_RDWR)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except OSError:
            return True
        finally:
            os.close(fd)


def daemonize(work_dir: Path) -> None:
    """标准双 fork。

    第一次 fork + setsid 让进程脱离控制终端；第二次 fork 确保新进程不是会话组长，
    从而永远无法再获得一个控制终端（否则终端关闭时会收到 SIGHUP）。
    """
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)

    os.chdir(work_dir)
    os.umask(0o027)

    # 重定向标准流：不这么做的话，父 shell 退出后任何 print 都会触发 EBADF，
    # 而且守护进程会一直占着终端的文件描述符。
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        try:
            os.dup2(devnull, fd)
        except OSError:
            pass
    if devnull > 2:
        os.close(devnull)


def install_signal_handlers(on_stop, on_reload) -> None:
    def _stop(signum: int, _frame: object) -> None:
        log.info("收到信号 %s，开始优雅退出", signal.Signals(signum).name)
        on_stop()

    def _reload(signum: int, _frame: object) -> None:
        log.info("收到 SIGHUP，重新加载配置")
        on_reload()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, _reload)
    # 忽略 SIGPIPE：客户端中途断开时，写响应会触发它并默认杀死进程。
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)


def send_signal(pid: int, sig: signal.Signals) -> bool:
    try:
        os.kill(pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        print(f"无权向 pid {pid} 发送信号（需要相同用户或 root）", file=sys.stderr)
        return False
