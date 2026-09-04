"""`.env` 文件加载。

为什么自己写而不用 python-dotenv：本项目的依赖只有 PyYAML，为了一个几十行的解析器
引入新依赖不划算，而且供应链上多一个包就多一分风险 —— 这个文件读的是密钥。

安全约定（与 config.yaml 一致）：
- 文件权限若 group/world 可读，直接拒绝加载。它存的是密钥。
- **已存在的环境变量优先**，`.env` 不覆盖。这样临时 `AUTORUN_KEY_X=... python -m autorun`
  能压过文件里的值，符合其他工具的惯例，也避免文件里的旧值悄悄盖掉你显式指定的值。
- 只记录加载了哪些**键名**，绝不记录值。
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .errors import ConfigError

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# 未加引号的值里，被空白隔开的 # 之后视为行内注释
_INLINE_COMMENT_RE = re.compile(r"\s+#.*$")

DEFAULT_ENV_FILENAME = ".env"


class EnvLoadResult:
    """加载结果。`applied` 是真正写入环境的键名，`skipped` 是因已存在而跳过的。"""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.applied: list[str] = []
        self.skipped: list[str] = []

    @property
    def loaded(self) -> bool:
        return self.path is not None

    def summary(self) -> str:
        if not self.loaded:
            return "未加载 .env（文件不存在，将只使用现有环境变量）"
        parts = [f"已加载 {self.path}"]
        if self.applied:
            parts.append(f"生效 {len(self.applied)} 项: {', '.join(self.applied)}")
        if self.skipped:
            parts.append(f"跳过 {len(self.skipped)} 项（环境中已存在，优先使用）: {', '.join(self.skipped)}")
        if not self.applied and not self.skipped:
            parts.append("文件中没有有效条目")
        return " | ".join(parts)


def _unquote(raw: str, where: str) -> str:
    """处理引号与转义。

    - 单引号：完全字面量，内部不做任何转义处理（适合含 `$`、`\\` 的密钥）
    - 双引号：处理 \\n \\t \\r \\\\ \\" 四类常见转义
    - 无引号：去掉行内注释与首尾空白
    """
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        body = value[1:-1]
        if value[0] == "'":
            return body
        return (
            body.replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\r", "\r")
            .replace('\\"', '"')
            .replace("\\\\", "\\")
        )
    if value.startswith(("'", '"')):
        # 引号没闭合。静默当成字面量会让密钥带上一个多余的引号，认证莫名失败，
        # 排查起来很费时间，所以直接报错。
        raise ConfigError(f"{where}: 引号未闭合")
    return _INLINE_COMMENT_RE.sub("", value)


def parse(text: str, *, source: str = ".env") -> dict[str, str]:
    """解析 .env 内容。语法错误直接报错，不静默跳过。"""
    out: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        where = f"{source}:{lineno}"
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # 兼容 `export KEY=value` 写法，方便同一个文件也能被 shell source
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].lstrip()
        if "=" not in stripped:
            raise ConfigError(f"{where}: 缺少 `=`，无法解析 {stripped!r}")
        key, _, raw_value = stripped.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            raise ConfigError(f"{where}: 非法的变量名 {key!r}")
        if key in out:
            # 重复定义时后者覆盖前者是常见实现，但对密钥来说"到底哪个生效"必须明确。
            raise ConfigError(f"{where}: 变量 {key!r} 重复定义")
        out[key] = _unquote(raw_value, where)
    return out


def load(
    path: str | os.PathLike[str] | None,
    *,
    required: bool = False,
    override: set[str] | None = None,
) -> EnvLoadResult:
    """把 .env 加载进 os.environ。已存在的变量默认不覆盖。

    `required` 为真时（用户显式指定了 --env-file），文件不存在即报错；否则静默跳过，
    因为密钥也可以直接由环境变量或 systemd 的 EnvironmentFile 提供。

    `override` 用于 SIGHUP 重载：只有上一次确实由 .env 提供的键才允许被新值覆盖。
    这样密钥轮换可以热生效，同时不会踩掉用户在 shell 里显式指定的变量。
    """
    if path is None:
        return EnvLoadResult(None)
    p = Path(path).expanduser()
    if not p.is_file():
        if required:
            raise ConfigError(f"指定的 env 文件不存在: {p}")
        return EnvLoadResult(None)

    mode = p.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        raise ConfigError(
            f"{p} 权限过宽（{stat.filemode(mode)}），它保存密钥，请执行 chmod 600 {p}"
        )

    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"无法读取 {p}: {exc}") from exc

    allowed = override or set()
    result = EnvLoadResult(p)
    for key, value in parse(text, source=str(p)).items():
        if key in os.environ and key not in allowed:
            result.skipped.append(key)
            continue
        os.environ[key] = value
        result.applied.append(key)
    return result


def default_path_for_config(config_path: str | os.PathLike[str]) -> Path:
    """默认在项目根目录找 `.env`，即配置文件的上两级（config/config.yaml -> 项目根）。

    与 config.py 中相对路径的解析基准保持一致，这样不管从哪个目录启动服务，
    找到的都是同一个 .env。
    """
    cfg = Path(config_path).expanduser().resolve()
    return cfg.parent.parent / DEFAULT_ENV_FILENAME
