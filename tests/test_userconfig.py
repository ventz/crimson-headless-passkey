"""Per-user config.toml: non-secret only; never the real ~/.config."""

import pytest

from crimson_headless_passkey import userconfig
from crimson_headless_passkey.envfile import merged_env
from crimson_headless_passkey.errors import ConfigError


def test_default_path_honors_env_override(tmp_path, monkeypatch):
    cfg = tmp_path / "mine.toml"
    monkeypatch.setenv("CRIMSON_HEADLESS_PASSKEY_CONFIG", str(cfg))
    assert userconfig.default_config_path() == cfg


def test_loads_username_and_upn(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('username = "a@example.edu"\nupn = "a@harvard.edu"\n', encoding="utf-8")
    monkeypatch.setenv("CRIMSON_HEADLESS_PASSKEY_CONFIG", str(cfg))
    data = userconfig.load_user_config()
    assert data["username"] == "a@example.edu"
    assert data["upn"] == "a@harvard.edu"
    env = userconfig.as_env(data)
    assert env["CRIMSON_HEADLESS_PASSKEY_USERNAME"] == "a@example.edu"
    assert env["CRIMSON_HEADLESS_PASSKEY_UPN"] == "a@harvard.edu"


def test_secret_looking_key_is_rejected(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('password = "hunter2hunter2"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="secret"):
        userconfig.load_user_config(cfg)


def test_secret_looking_value_is_rejected(tmp_path):
    cfg = tmp_path / "config.toml"
    # A JWT-shaped value in username must be refused.
    cfg.write_text(
        'username = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepartxx"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="token or key"):
        userconfig.load_user_config(cfg)


def test_merged_env_precedence(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('username = "from-config"\n', encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("CRIMSON_HEADLESS_PASSKEY_USERNAME=from-dotenv\n", encoding="utf-8")
    monkeypatch.setenv("CRIMSON_HEADLESS_PASSKEY_CONFIG", str(cfg))
    monkeypatch.delenv("CRIMSON_HEADLESS_PASSKEY_USERNAME", raising=False)
    merged = merged_env(env_file, environ={}, config_file=cfg)
    assert merged["CRIMSON_HEADLESS_PASSKEY_USERNAME"] == "from-dotenv"
    merged = merged_env(
        env_file,
        environ={"CRIMSON_HEADLESS_PASSKEY_USERNAME": "from-env"},
        config_file=cfg,
    )
    assert merged["CRIMSON_HEADLESS_PASSKEY_USERNAME"] == "from-env"


def test_missing_config_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("CRIMSON_HEADLESS_PASSKEY_CONFIG", str(tmp_path / "nope.toml"))
    assert userconfig.load_user_config() == {}
