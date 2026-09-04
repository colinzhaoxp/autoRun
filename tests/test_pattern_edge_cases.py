"""补充：pattern 的边界写法。

`pattern: ""` 是一个真实踩过的坑 —— 写的人想表达"不限制"，但空正则在 fullmatch 下
只匹配空字符串，效果是拒绝所有输入。语义正好相反，所以必须在启动时就拦住。
"""

from __future__ import annotations

import re

import pytest

from autorun.commands import prepare_alias, validate_params
from autorun.config import CommandSpec, ParamSpec
from autorun.errors import ConfigError, ValidationError
from conftest import base_config, write_config


def test_empty_pattern_rejected_at_startup(tmp_path):
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["anything"] = {
        "shell": "/bin/echo {msg}",
        "params": {"msg": {"required": True, "pattern": "", "max_length": 32}},
    }
    with pytest.raises(ConfigError, match=r"pattern 为空") as exc:
        config.load(write_config(tmp_path, data))
    # 报错要给出可直接照抄的正确写法，否则用户只会换个错法再试一次
    assert "^.*$" in str(exc.value)


def test_empty_pattern_would_reject_everything():
    """说明为什么要拦：空正则确实只放过空字符串。"""
    spec = CommandSpec(
        name="x", shell="/bin/echo {v}", params={"v": ParamSpec("v", True, re.compile(""), 32)}
    )
    assert validate_params(spec, {"v": ""}) == {"v": ""}
    for value in ("hello", "v1.0.0", "a"):
        with pytest.raises(ValidationError, match="不满足允许的格式"):
            validate_params(spec, {"v": value})


def test_permissive_pattern_accepts_arbitrary_text(make_config, tmp_path):
    """`^.*$` 是"不限制"的正确写法。"""
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["free"] = {
        "shell": "/bin/echo {msg}",
        "params": {"msg": {"required": True, "pattern": "^.*$", "max_length": 64}},
        "mode": "sync",
    }
    cfg = config.load(write_config(tmp_path, data))
    for value in ("hello world", "a b; whoami", "$(id)", "`id`", "x|nc evil 1", "中文", ""):
        prepared = prepare_alias(cfg, "free", {"msg": value})
        assert prepared.argv[0] == "/bin/bash"


def test_permissive_pattern_still_blocks_control_chars(make_config, tmp_path):
    """pattern 放宽不等于放弃防线：控制字符始终无条件拒绝。"""
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["free"] = {
        "shell": "/bin/echo {msg}",
        "params": {"msg": {"required": True, "pattern": "^.*$", "max_length": 64}},
    }
    cfg = config.load(write_config(tmp_path, data))
    for value in ("a\nid", "a\x00id", "a\rid"):
        with pytest.raises(ValidationError, match="控制字符"):
            prepare_alias(cfg, "free", {"msg": value})


def test_permissive_pattern_values_arrive_as_single_argument(client, tmp_path):
    """端到端确认：宽松 pattern 下 shell 元字符仍是字面量，不会被解释执行。

    `loose` 别名的 pattern 是 `^[ -~]+$`（任意可打印 ASCII），等价于放开限制。
    """
    for value in ("a b; whoami", "$(id)", "`id`", "x | nc evil 1", "a && id"):
        status, body, _ = client.post("/v1/exec", {"alias": "loose", "params": {"msg": value}})
        assert status == 200, (value, body)
        tail = body["data"]["output_tail"]
        assert value in tail
        # 若发生命令替换/串联，输出里会出现 uid=
        assert "uid=" not in tail


def test_max_length_still_applies_with_permissive_pattern(make_config, tmp_path):
    from autorun import config

    data = base_config(tmp_path)
    data["commands"]["free"] = {
        "shell": "/bin/echo {msg}",
        "params": {"msg": {"required": True, "pattern": "^.*$", "max_length": 10}},
    }
    cfg = config.load(write_config(tmp_path, data))
    prepare_alias(cfg, "free", {"msg": "0123456789"})
    with pytest.raises(ValidationError, match="超过上限"):
        prepare_alias(cfg, "free", {"msg": "01234567890"})
