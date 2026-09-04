"""错误类型体系：每个异常自带 HTTP 状态码与稳定的机器可读 error code。

设计要点：客户端可见信息与内部信息分离。`message` 是给客户端看的，不含内部路径、
配置值或堆栈；真正的诊断信息由调用方写进服务日志（由 request_id 关联）。
"""

from __future__ import annotations


class AppError(Exception):
    """所有业务异常的基类。"""

    status: int = 500
    code: str = "INTERNAL_ERROR"

    def __init__(self, message: str = "", **extra: object) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.extra = extra


class ConfigError(AppError):
    """配置加载/校验失败。这个异常只在启动或 reload 时抛出，不会走到 HTTP 层。"""

    status = 500
    code = "CONFIG_ERROR"


# --- 4xx：客户端错误 ------------------------------------------------------


class BadRequest(AppError):
    status = 400
    code = "BAD_REQUEST"


class Unauthorized(AppError):
    """缺失或错误的密钥。message 刻意保持模糊，不区分两种情况。"""

    status = 401
    code = "UNAUTHORIZED"


class Forbidden(AppError):
    """IP 未白名单，或该 key 无权做此操作。"""

    status = 403
    code = "FORBIDDEN"


class NotFound(AppError):
    status = 404
    code = "NOT_FOUND"


class AliasNotFound(NotFound):
    code = "ALIAS_NOT_FOUND"


class JobNotFound(NotFound):
    code = "JOB_NOT_FOUND"


class MethodNotAllowed(AppError):
    status = 405
    code = "METHOD_NOT_ALLOWED"


class Conflict(AppError):
    """singleton 冲突，或任务已退出无法再发信号。"""

    status = 409
    code = "CONFLICT"


class PayloadTooLarge(AppError):
    status = 413
    code = "PAYLOAD_TOO_LARGE"


class UnsupportedMediaType(AppError):
    status = 415
    code = "UNSUPPORTED_MEDIA_TYPE"


class ValidationError(AppError):
    """参数存在但不满足声明的 pattern / max_length / 类型约束。

    这是注入防线的主要出口：任何可疑的参数值都在这里被拒绝，绝不到达 shell。
    """

    status = 422
    code = "VALIDATION_ERROR"


class RateLimited(AppError):
    status = 429
    code = "RATE_LIMITED"

    def __init__(self, message: str = "", retry_after: int = 60) -> None:
        super().__init__(message, retry_after=retry_after)
        self.retry_after = retry_after


# --- 5xx：服务端 ----------------------------------------------------------


class ServiceUnavailable(AppError):
    """达到并发上限等暂时性拒绝，客户端可重试。"""

    status = 503
    code = "SERVICE_UNAVAILABLE"

    def __init__(self, message: str = "", retry_after: int = 10) -> None:
        super().__init__(message, retry_after=retry_after)
        self.retry_after = retry_after


class ExecutionError(AppError):
    """无法启动进程（可执行文件不存在、cwd 不存在、磁盘写满等）。"""

    status = 500
    code = "EXECUTION_ERROR"
