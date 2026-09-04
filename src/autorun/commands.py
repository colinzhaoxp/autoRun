"""命令构造：把"别名 + 参数"翻译成可执行的 argv。

**这是真正的注入防线，也是本项目最需要评审的文件。**

三条不可动摇的规则：

1. 客户端永远无法提供命令体本身，只能提供别名和已声明的参数值。命令文本、cwd、
   run_as 全部来自服务端配置。
2. `argv` 形式的别名以 `shell=False` 执行 —— 没有 shell，就没有元字符可利用，
   连转义都不需要。这是首选形式。
3. `shell` 形式的别名，参数代入**不是**字符串格式化。每个值先经该参数声明的正则
   `fullmatch` 与长度校验，通过后再用 `shlex.quote` 包裹。用 `str.format` 或 f-string
   拼命令是本类服务最典型的 RCE 成因，本模块刻意不提供那条路径。
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Mapping

from .config import CommandSpec, Config, ExecutionConfig, RunAs
from .errors import AliasNotFound, Forbidden, ValidationError

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# 控制字符（除普通空格外）一律拒绝。NUL 会截断 C 字符串，换行会在 shell 语境下
# 变成新的一条命令 —— 即使某个宽松的 pattern 放过了它们，这里也要挡住。
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


@dataclass(frozen=True)
class PreparedCommand:
    """已完成校验、可以直接交给 executor 启动的命令。"""

    argv: tuple[str, ...]
    cwd: str
    display: str
    timeout_sec: int
    alias: str | None = None
    singleton: bool = False
    mode: str = "background"
    run_as: RunAs = field(default_factory=RunAs)
    params: dict[str, str] = field(default_factory=dict)


def _reject_bad_chars(name: str, value: str) -> None:
    if _CONTROL_CHARS.search(value):
        raise ValidationError(f"参数 {name!r} 含控制字符，已拒绝")


def validate_params(spec: CommandSpec, given: Mapping[str, Any]) -> dict[str, str]:
    """校验并归一化参数值。任何不确定的输入都在这里被拒绝。"""
    if not isinstance(given, Mapping):
        raise ValidationError("params 必须是对象")

    # 未声明的参数是错误，不是"忽略掉就好"。静默忽略会让调用方以为自己的输入生效了。
    unknown = set(given) - set(spec.params)
    if unknown:
        raise ValidationError(f"命令 {spec.name!r} 不接受参数: {sorted(unknown)}")

    out: dict[str, str] = {}
    for name, pspec in spec.params.items():
        if name in given:
            raw = given[name]
            # 只接受字符串与数字。传 dict/list 进来说明调用方误解了接口。
            if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
                raise ValidationError(f"参数 {name!r} 必须是字符串或数字")
            value = str(raw)
        elif pspec.default is not None:
            value = pspec.default
        elif pspec.required:
            raise ValidationError(f"缺少必填参数 {name!r}")
        else:
            continue

        _reject_bad_chars(name, value)
        if len(value) > pspec.max_length:
            raise ValidationError(
                f"参数 {name!r} 长度 {len(value)} 超过上限 {pspec.max_length}"
            )
        # fullmatch 而非 search/match：`^...$` 之外的锚定疏漏（比如 pattern 忘了写 $）
        # 不会导致尾部被塞进 `; rm -rf /`。
        if not pspec.pattern.fullmatch(value):
            raise ValidationError(
                f"参数 {name!r} 不满足允许的格式 ({pspec.pattern.pattern})"
            )
        out[name] = value
    return out


def _render_shell(body: str, values: Mapping[str, str]) -> str:
    """把校验通过的参数代入 shell 命令体。

    实现上显式扫描占位符逐个替换，而不用 `str.format`：`format` 会解释 `{0}`、
    `{a.b}`、`{a!r}` 等语法，也会对命令体里合法出现的 `{}`（如 awk 脚本、find -exec）
    报错或误替换。显式扫描只认 `{标识符}` 这一种形态，其余字符原样保留。
    """

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        # 走到这里说明配置校验漏了，属于服务端 bug 而非客户端输入问题。
        if name not in values:
            raise ValidationError(f"占位符 {{{name}}} 无对应参数值")
        return shlex.quote(values[name])

    return _PLACEHOLDER.sub(repl, body)


def _render_argv(argv: tuple[str, ...], values: Mapping[str, str]) -> tuple[str, ...]:
    """argv 形式的占位符替换。

    不做 shlex.quote —— 这里没有 shell 会去解释引号，加引号反而会把引号本身当作
    参数内容传给程序。每个元素始终是**一个**参数，这正是 argv 形式安全的原因。
    """

    def repl(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in values:
            raise ValidationError(f"占位符 {{{name}}} 无对应参数值")
        return values[name]

    return tuple(_PLACEHOLDER.sub(repl, item) for item in argv)


def _clamp_timeout(requested: int | None, spec_timeout: int | None, ex: ExecutionConfig) -> int:
    base = spec_timeout or ex.default_timeout_sec
    if requested is None:
        return min(base, ex.max_timeout_sec)
    if requested <= 0:
        raise ValidationError("timeout_sec 必须为正数")
    # 客户端可以缩短，但不能突破服务端上限。
    return min(requested, ex.max_timeout_sec)


def prepare_alias(
    cfg: Config,
    alias: str,
    params: Mapping[str, Any] | None,
    *,
    requested_timeout: int | None = None,
    requested_mode: str | None = None,
) -> PreparedCommand:
    spec = cfg.commands.get(alias)
    if spec is None:
        raise AliasNotFound(f"未定义的命令别名: {alias!r}")

    values = validate_params(spec, params or {})
    ex = cfg.execution

    if spec.uses_shell:
        rendered = _render_shell(spec.shell or "", values)
        argv = (ex.shell, *ex.shell_args, rendered)
        display = rendered
    else:
        argv = _render_argv(spec.argv, values)
        display = " ".join(shlex.quote(a) for a in argv)

    mode = requested_mode or spec.mode
    if mode not in ("background", "sync"):
        raise ValidationError("mode 只能是 background 或 sync")

    return PreparedCommand(
        argv=argv,
        cwd=spec.cwd or ex.default_cwd,
        display=display,
        timeout_sec=_clamp_timeout(requested_timeout, spec.timeout_sec, ex),
        alias=alias,
        singleton=spec.singleton,
        mode=mode,
        run_as=spec.run_as or ex.run_as,
        params=values,
    )


def prepare_raw(
    cfg: Config,
    command: Any,
    *,
    cwd: str | None = None,
    requested_timeout: int | None = None,
    requested_mode: str | None = None,
) -> PreparedCommand:
    """构造裸命令。

    这条路径本质上就是受认证的 RCE，没有任何办法把它变成"安全的"。因此它默认关闭，
    需要全局开关与该 key 的 allow_raw 双重许可，唯一的真实控制手段是认证与审计。
    denylist 只是纵深防御 —— 它能挡住手滑打出的 `rm -rf /`，挡不住有意的绕过
    （`rm -fr /`、变量拼接、base64 解码执行都能躲开正则）。不要把它当成边界。
    """
    if not cfg.security.allow_raw_commands:
        raise Forbidden("本服务未开启裸命令执行（security.allow_raw_commands）")
    if not isinstance(command, str) or not command.strip():
        raise ValidationError("command 必须是非空字符串")
    if "\x00" in command:
        raise ValidationError("command 含 NUL 字符")

    for pat in cfg.security.raw_command_denylist:
        if pat.search(command):
            raise Forbidden(f"命令被拒绝规则拦截: {pat.pattern}")

    ex = cfg.execution
    # cwd 只允许在配置声明的目录树内？—— 不做该限制，因为裸命令本身就能 cd。
    # 加这层检查只会给出虚假的安全感。
    mode = requested_mode or "background"
    if mode not in ("background", "sync"):
        raise ValidationError("mode 只能是 background 或 sync")

    return PreparedCommand(
        argv=(ex.shell, *ex.shell_args, command),
        cwd=cwd or ex.default_cwd,
        display=command,
        timeout_sec=_clamp_timeout(requested_timeout, None, ex),
        alias=None,
        singleton=False,
        mode=mode,
        run_as=ex.run_as,
        params={},
    )


def describe_for_key(cfg: Config, allowed: tuple[str, ...]) -> list[dict[str, Any]]:
    """列出某个密钥可见的别名。不暴露命令体本身 —— 调用方无需知道，
    而且泄露服务端路径与脚本名会给攻击者提供侦察信息。"""
    wildcard = "*" in allowed
    out: list[dict[str, Any]] = []
    for name, spec in sorted(cfg.commands.items()):
        if not wildcard and name not in allowed:
            continue
        out.append(
            {
                "alias": name,
                "description": spec.description,
                "mode": spec.mode,
                "singleton": spec.singleton,
                "timeout_sec": spec.timeout_sec or cfg.execution.default_timeout_sec,
                "params": {
                    pname: {
                        "required": p.required,
                        "pattern": p.pattern.pattern,
                        "max_length": p.max_length,
                        "default": p.default,
                    }
                    for pname, p in spec.params.items()
                },
            }
        )
    return out
