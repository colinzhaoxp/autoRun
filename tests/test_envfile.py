""".env 加载测试。密钥文件的解析既要宽容（兼容常见写法）又要严格（不静默出错）。"""

from __future__ import annotations

import os
import stat

import pytest

from autorun import envfile
from autorun.errors import ConfigError


def write_env(tmp_path, content: str, mode: int = 0o600):
    p = tmp_path / ".env"
    p.write_text(content, encoding="utf-8")
    os.chmod(p, mode)
    return p


def test_basic_load(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTORUN_TEST_A", raising=False)
    path = write_env(tmp_path, "AUTORUN_TEST_A=hello-world\n")
    result = envfile.load(path)
    assert result.loaded
    assert result.applied == ["AUTORUN_TEST_A"]
    assert os.environ["AUTORUN_TEST_A"] == "hello-world"


def test_comments_and_blank_lines_ignored(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTORUN_TEST_B", raising=False)
    write_env(tmp_path, "# 注释\n\n   \nAUTORUN_TEST_B=v1\n")
    envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_TEST_B"] == "v1"


def test_export_prefix_supported(tmp_path, monkeypatch):
    """兼容 `export KEY=v`，这样同一个文件也能被 shell source。"""
    monkeypatch.delenv("AUTORUN_TEST_C", raising=False)
    write_env(tmp_path, "export AUTORUN_TEST_C=v2\n")
    envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_TEST_C"] == "v2"


def test_quotes_preserve_special_characters(tmp_path, monkeypatch):
    """密钥里出现 #、空格、$ 时必须靠引号完整保留。"""
    for key in ("AUTORUN_Q1", "AUTORUN_Q2", "AUTORUN_Q3"):
        monkeypatch.delenv(key, raising=False)
    write_env(
        tmp_path,
        'AUTORUN_Q1="a b # not-a-comment"\n'
        "AUTORUN_Q2='literal$value\\n'\n"
        'AUTORUN_Q3="line1\\nline2"\n',
    )
    envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_Q1"] == "a b # not-a-comment"
    # 单引号是完全字面量，不做转义
    assert os.environ["AUTORUN_Q2"] == "literal$value\\n"
    # 双引号处理 \n
    assert os.environ["AUTORUN_Q3"] == "line1\nline2"


def test_inline_comment_stripped_for_unquoted(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTORUN_TEST_D", raising=False)
    write_env(tmp_path, "AUTORUN_TEST_D=abc123   # 这是注释\n")
    envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_TEST_D"] == "abc123"


def test_hash_without_leading_space_is_kept(tmp_path, monkeypatch):
    """`abc#def` 不是注释 —— 只有前面有空白的 # 才算。"""
    monkeypatch.delenv("AUTORUN_TEST_E", raising=False)
    write_env(tmp_path, "AUTORUN_TEST_E=abc#def\n")
    envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_TEST_E"] == "abc#def"


def test_existing_env_wins_by_default(tmp_path, monkeypatch):
    """已存在的环境变量优先，便于临时覆盖，也避免文件里的旧值悄悄生效。"""
    monkeypatch.setenv("AUTORUN_TEST_F", "from-shell")
    write_env(tmp_path, "AUTORUN_TEST_F=from-file\n")
    result = envfile.load(tmp_path / ".env")
    assert os.environ["AUTORUN_TEST_F"] == "from-shell"
    assert result.skipped == ["AUTORUN_TEST_F"]
    assert result.applied == []


def test_override_only_applies_to_listed_keys(tmp_path, monkeypatch):
    """SIGHUP 重载：只覆盖上次由 .env 提供的键，不踩 shell 里显式指定的变量。"""
    monkeypatch.setenv("AUTORUN_FROM_FILE", "old-file-value")
    monkeypatch.setenv("AUTORUN_FROM_SHELL", "shell-value")
    write_env(tmp_path, "AUTORUN_FROM_FILE=new-file-value\nAUTORUN_FROM_SHELL=hijacked\n")
    envfile.load(tmp_path / ".env", override={"AUTORUN_FROM_FILE"})
    assert os.environ["AUTORUN_FROM_FILE"] == "new-file-value"
    assert os.environ["AUTORUN_FROM_SHELL"] == "shell-value"


def test_group_readable_file_rejected(tmp_path):
    """.env 存密钥，group/world 可读即视为泄露风险。"""
    path = write_env(tmp_path, "AUTORUN_X=y\n", mode=0o644)
    with pytest.raises(ConfigError, match="权限过宽"):
        envfile.load(path)


def test_missing_file_is_not_an_error(tmp_path):
    """密钥也可以直接由环境变量或 systemd EnvironmentFile 提供。"""
    result = envfile.load(tmp_path / "nope.env")
    assert not result.loaded
    assert "未加载" in result.summary()


def test_missing_file_is_error_when_explicit(tmp_path):
    """用户显式指定了 --env-file 却不存在，属于配置错误而非可忽略情况。"""
    with pytest.raises(ConfigError, match="不存在"):
        envfile.load(tmp_path / "nope.env", required=True)


def test_line_without_equals_reported_with_lineno(tmp_path):
    with pytest.raises(ConfigError, match=r":3: 缺少 `=`"):
        envfile.parse("A=1\nB=2\nthis is bad\n", source="x")


def test_invalid_key_name_rejected(tmp_path):
    for bad in ("1KEY=v", "MY-KEY=v", "MY KEY=v"):
        with pytest.raises(ConfigError, match="非法的变量名"):
            envfile.parse(bad, source="x")


def test_duplicate_key_rejected():
    """对密钥来说"到底哪个生效"必须明确，不能靠"后者覆盖前者"的隐式规则。"""
    with pytest.raises(ConfigError, match="重复定义"):
        envfile.parse("K=1\nK=2\n", source="x")


def test_unclosed_quote_rejected():
    """静默当字面量会让密钥多带一个引号，认证莫名失败且极难排查。"""
    with pytest.raises(ConfigError, match="引号未闭合"):
        envfile.parse('K="abc\n', source="x")


def test_empty_value_allowed():
    assert envfile.parse("K=\n", source="x") == {"K": ""}


def test_default_path_is_project_root():
    """默认位置与 config.py 中相对路径的解析基准一致（配置文件的上两级）。"""
    got = envfile.default_path_for_config("/srv/app/config/config.yaml")
    assert str(got) == "/srv/app/.env"


def test_cli_loads_env_file_for_config_expansion(tmp_path, monkeypatch):
    """端到端：.env 提供密钥，config.yaml 用 ${VAR} 引用，validate 应通过。"""
    from conftest import base_config, write_config

    monkeypatch.delenv("AUTORUN_KEY_FROM_ENVFILE", raising=False)
    data = base_config(tmp_path)
    data["auth"]["keys"][0]["key"] = "${AUTORUN_KEY_FROM_ENVFILE}"
    cfg_path = write_config(tmp_path, data)
    write_env(tmp_path, "AUTORUN_KEY_FROM_ENVFILE=key-loaded-from-dotenv-file\n")

    from autorun.cli import main

    assert main(["-c", str(cfg_path), "validate"]) == 0
    assert os.environ["AUTORUN_KEY_FROM_ENVFILE"] == "key-loaded-from-dotenv-file"


def test_cli_no_env_file_flag_skips_loading(tmp_path, monkeypatch):
    from conftest import base_config, write_config

    monkeypatch.delenv("AUTORUN_KEY_SKIPPED", raising=False)
    data = base_config(tmp_path)
    data["auth"]["keys"][0]["key"] = "${AUTORUN_KEY_SKIPPED}"
    cfg_path = write_config(tmp_path, data)
    write_env(tmp_path, "AUTORUN_KEY_SKIPPED=should-not-be-loaded\n")

    from autorun.cli import main

    # --no-env-file 后 ${VAR} 无从展开，validate 必须失败并给出可操作提示
    assert main(["-c", str(cfg_path), "--no-env-file", "validate"]) == 1
    assert "AUTORUN_KEY_SKIPPED" not in os.environ


def test_undefined_var_error_mentions_env_file(tmp_path, monkeypatch):
    from autorun import config
    from conftest import base_config, write_config

    monkeypatch.delenv("AUTORUN_NOT_SET_ANYWHERE", raising=False)
    data = base_config(tmp_path)
    data["auth"]["keys"][0]["key"] = "${AUTORUN_NOT_SET_ANYWHERE}"
    with pytest.raises(ConfigError, match=r"\.env"):
        config.load(write_config(tmp_path, data))
