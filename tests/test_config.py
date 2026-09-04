"""配置校验测试。每个用例对应一个真实故障模式，注释说明它拦的是什么。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from autorun import config
from autorun.errors import ConfigError
from conftest import base_config, write_config


def load_with(tmp_path: Path, **overrides):
    return config.load(write_config(tmp_path, base_config(tmp_path, **overrides)))


def test_valid_config_loads(cfg):
    assert cfg.server.port > 0
    assert {k.id for k in cfg.auth.keys} == {"admin", "ci"}
    assert "rollback" in cfg.commands


def test_group_readable_config_rejected(tmp_path):
    """配置涉及密钥，group/world 可读即视为泄露风险。"""
    path = write_config(tmp_path, base_config(tmp_path))
    os.chmod(path, 0o644)
    with pytest.raises(ConfigError, match="权限过宽"):
        config.load(path)


def test_undefined_env_var_aborts(tmp_path):
    """拦的故障：密钥环境变量忘记 export 时，静默变成空串会让认证形同虚设。"""
    data = base_config(tmp_path)
    data["auth"]["keys"][0]["key"] = "${AUTORUN_DEFINITELY_NOT_SET_12345}"
    with pytest.raises(ConfigError, match="环境变量"):
        config.load(write_config(tmp_path, data))


def test_env_var_expansion_works(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTORUN_TEST_KEY", "env-provided-key-0123456789abcdef")
    data = base_config(tmp_path)
    data["auth"]["keys"][0]["key"] = "${AUTORUN_TEST_KEY}"
    cfg = config.load(write_config(tmp_path, data))
    assert cfg.auth.keys[0].key == "env-provided-key-0123456789abcdef"


def test_short_key_rejected(tmp_path):
    """短密钥可被暴力破解，宁可启动失败也不上线弱密钥。"""
    with pytest.raises(ConfigError, match="min_key_length"):
        load_with(tmp_path, auth={"min_key_length": 64})


def test_empty_ip_whitelist_rejected(tmp_path):
    """fail closed：空白名单若语义为"全放通"，一次误删就等于全网开放。"""
    with pytest.raises(ConfigError, match="ip_whitelist"):
        load_with(tmp_path, security={"ip_whitelist": []})


def test_malformed_cidr_aborts_startup(tmp_path):
    """静默跳过写错的网段，会让运维误以为某条限制生效了。"""
    with pytest.raises(ConfigError, match="无法解析网段"):
        load_with(tmp_path, security={"ip_whitelist": ["127.0.0.1/33"]})


def test_duplicate_key_id_rejected(tmp_path):
    """重复 id 会让审计日志无法区分调用方。"""
    data = base_config(tmp_path)
    data["auth"]["keys"][1]["id"] = "admin"
    with pytest.raises(ConfigError, match="重复"):
        config.load(write_config(tmp_path, data))


def test_empty_keys_rejected(tmp_path):
    with pytest.raises(ConfigError, match="不能为空"):
        load_with(tmp_path, auth={"keys": []})


def test_command_needs_exactly_one_of_shell_or_argv(tmp_path):
    for bad in ({"shell": "echo x", "argv": ["/bin/echo"]}, {"description": "空"}):
        data = base_config(tmp_path)
        data["commands"]["broken"] = bad
        with pytest.raises(ConfigError, match="恰好指定"):
            config.load(write_config(tmp_path, data))


def test_undeclared_placeholder_rejected(tmp_path):
    """拦的故障：命令里写了 {tag} 却忘记声明 params.tag，字面量会被传给 shell。"""
    data = base_config(tmp_path)
    data["commands"]["broken"] = {"shell": "./deploy.sh {tag}"}
    with pytest.raises(ConfigError, match="未在 params 中声明"):
        config.load(write_config(tmp_path, data))


def test_unused_param_rejected(tmp_path):
    """拦的故障：占位符名拼错导致参数被静默忽略，调用方以为自己的值生效了。"""
    data = base_config(tmp_path)
    data["commands"]["broken"] = {
        "shell": "./deploy.sh {tgs}",
        "params": {
            "tgs": {"pattern": "^v.*$"},
            "tag": {"pattern": "^v.*$"},
        },
    }
    with pytest.raises(ConfigError, match="未被命令引用"):
        config.load(write_config(tmp_path, data))


def test_param_without_pattern_rejected(tmp_path):
    """没有正则白名单的参数不允许存在 —— 那等于把任意值代入命令。"""
    data = base_config(tmp_path)
    data["commands"]["broken"] = {
        "shell": "./deploy.sh {tag}",
        "params": {"tag": {"required": True, "max_length": 10}},
    }
    with pytest.raises(ConfigError, match="必须声明 pattern"):
        config.load(write_config(tmp_path, data))


def test_invalid_regex_rejected(tmp_path):
    data = base_config(tmp_path)
    data["commands"]["broken"] = {
        "shell": "./x.sh {tag}",
        "params": {"tag": {"pattern": "^(unclosed"}},
    }
    with pytest.raises(ConfigError, match="无效"):
        config.load(write_config(tmp_path, data))


def test_default_must_satisfy_own_pattern(tmp_path):
    """默认值绕过自身校验等于开了个后门。"""
    data = base_config(tmp_path)
    data["commands"]["broken"] = {
        "shell": "./x.sh {tag}",
        "params": {"tag": {"pattern": r"^v[0-9]+$", "default": "not-a-version"}},
    }
    with pytest.raises(ConfigError, match="default"):
        config.load(write_config(tmp_path, data))


def test_acl_referencing_unknown_alias_rejected(tmp_path):
    """配置漂移：命令改名而 ACL 没跟上，会让该 key 静默失去权限。"""
    data = base_config(tmp_path)
    data["auth"]["keys"][1]["allowed_aliases"] = ["hello", "renamed_away"]
    with pytest.raises(ConfigError, match="不存在的命令"):
        config.load(write_config(tmp_path, data))


def test_nonexistent_run_as_user_rejected(tmp_path):
    """启动时就确认用户存在，而不是等第一次执行命令才失败。"""
    with pytest.raises(ConfigError, match="不存在用户"):
        load_with(tmp_path, execution={"run_as": {"user": "definitely_no_such_user_x"}})


def test_command_timeout_cannot_exceed_max(tmp_path):
    data = base_config(tmp_path)
    data["commands"]["hello"]["timeout_sec"] = 999999
    with pytest.raises(ConfigError, match="max_timeout_sec"):
        config.load(write_config(tmp_path, data))


def test_relative_paths_resolve_against_project_root(cfg):
    """相对路径按配置文件位置解析，不受进程 cwd 影响。"""
    assert Path(cfg.paths.state_dir).is_absolute()
    assert Path(cfg.logging.audit_file).is_absolute()


def test_warning_when_public_bind_without_tls(tmp_path):
    cfg = load_with(tmp_path, server={"host": "0.0.0.0"})
    assert any("明文" in w for w in cfg.warnings)


def test_no_warning_for_loopback(cfg):
    assert not any("明文" in w for w in cfg.warnings)


def test_raw_enabled_produces_warning(cfg):
    assert any("allow_raw_commands" in w for w in cfg.warnings)


def test_missing_file_reports_clearly(tmp_path):
    with pytest.raises(ConfigError, match="不存在"):
        config.load(tmp_path / "nope.yaml")


def test_invalid_log_level_rejected(tmp_path):
    with pytest.raises(ConfigError, match="logging.level"):
        load_with(tmp_path, logging={"level": "VERBOSE"})


def test_bad_yaml_reports_parse_error(tmp_path):
    path = tmp_path / "config" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("server: [unclosed\n", encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(ConfigError, match="YAML"):
        config.load(path)
