import os

import pytest

from crimson_headless_passkey.envfile import load_env_file, merged_env, parse_env
from crimson_headless_passkey.errors import ConfigError, InsecurePermissionsError

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")


def test_parse_env_formats():
    text = """
# comment
CRIMSON_HEADLESS_PASSKEY_URL=https://a.example
export CRIMSON_HEADLESS_PASSKEY_RP_ID = a.example
CRIMSON_HEADLESS_PASSKEY_USERNAME="some one # not a comment"
CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS=a.example,b.example  # trailing comment
EMPTY=
"""
    assert parse_env(text) == {
        "CRIMSON_HEADLESS_PASSKEY_URL": "https://a.example",
        "CRIMSON_HEADLESS_PASSKEY_RP_ID": "a.example",
        "CRIMSON_HEADLESS_PASSKEY_USERNAME": "some one # not a comment",
        "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS": "a.example,b.example",
        "EMPTY": "",
    }


@pytest.mark.parametrize("line", ["just text", "=value", "BAD KEY=x"])
def test_parse_env_rejects_malformed_lines(line):
    with pytest.raises(ConfigError, match=":1:"):
        parse_env(line)


def write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)
    return path


def test_only_this_tools_keys_are_loaded(tmp_path):
    env = write(tmp_path / ".env", "CRIMSON_HEADLESS_PASSKEY_RP_ID=a.example\nAWS_SECRET=x\n")
    assert load_env_file(env) == {"CRIMSON_HEADLESS_PASSKEY_RP_ID": "a.example"}


def test_real_environment_wins(tmp_path):
    env = write(
        tmp_path / ".env",
        "CRIMSON_HEADLESS_PASSKEY_RP_ID=file.example\nCRIMSON_HEADLESS_PASSKEY_USERNAME=file\n",
    )
    merged = merged_env(env, {"CRIMSON_HEADLESS_PASSKEY_RP_ID": "real.example"})
    assert merged["CRIMSON_HEADLESS_PASSKEY_RP_ID"] == "real.example"
    assert merged["CRIMSON_HEADLESS_PASSKEY_USERNAME"] == "file"


def test_dot_env_in_current_directory_is_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "CRIMSON_HEADLESS_PASSKEY_RP_ID" not in merged_env(environ={})
    write(tmp_path / ".env", "CRIMSON_HEADLESS_PASSKEY_RP_ID=cwd.example\n")
    assert merged_env(environ={})["CRIMSON_HEADLESS_PASSKEY_RP_ID"] == "cwd.example"


def test_explicit_env_file_must_exist(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        merged_env(tmp_path / "missing.env", {})


@posix_only
def test_env_file_writable_by_others_is_refused(tmp_path):
    env = write(tmp_path / ".env", "CRIMSON_HEADLESS_PASSKEY_URL=https://evil.example\n", 0o666)
    with pytest.raises(InsecurePermissionsError, match="chmod go-w"):
        load_env_file(env)


@posix_only
def test_world_readable_env_file_is_fine(tmp_path):
    # Settings are not secrets; only who can change them matters.
    env = write(tmp_path / ".env", "CRIMSON_HEADLESS_PASSKEY_RP_ID=a.example\n", 0o644)
    assert load_env_file(env)
