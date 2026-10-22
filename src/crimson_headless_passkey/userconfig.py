"""Per-user settings file: ``~/.config/crimson-headless-passkey/config.toml``.

**Non-secret settings only** (username, UPN, hosts, defaults). It never holds a
key, cookie, token or password: those live in the Keychain (or the opt-in
``file`` store). Keys that look secret are rejected outright, and values that
look like a token are rejected too, so a pasted secret fails loudly instead of
sitting in a plain file.

Precedence, highest first: flags, real environment, ``./.env``, this file,
built-in defaults. ``CRIMSON_HEADLESS_PASSKEY_CONFIG`` points at another file;
the tests always set it to a temp path, never the real ``~/.config``.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import redact
from .envfile import check_env_file
from .errors import ConfigError

ENV_CONFIG = "CRIMSON_HEADLESS_PASSKEY_CONFIG"
CONFIG_DIRNAME = "crimson-headless-passkey"
CONFIG_FILENAME = "config.toml"

# config.toml key -> the environment variable it fills (below the real env and .env).
SETTING_KEYS = {
    "username": "CRIMSON_HEADLESS_PASSKEY_USERNAME",
    "upn": "CRIMSON_HEADLESS_PASSKEY_UPN",
    "login_url": "CRIMSON_HEADLESS_PASSKEY_URL",
    "rp_id": "CRIMSON_HEADLESS_PASSKEY_RP_ID",
    "idp_hosts": "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS",
    "sso_hosts": "CRIMSON_HEADLESS_PASSKEY_SSO_HOSTS",
    "secret_store": "CRIMSON_HEADLESS_PASSKEY_SECRET_STORE",
    "data_dir": "CRIMSON_HEADLESS_PASSKEY_HOME",
}
# Command defaults (not settings): used by the CLI when the flag is absent.
DEFAULT_KEYS = {"timeout", "channel", "concurrency", "headless"}
ALLOWED_KEYS = set(SETTING_KEYS) | DEFAULT_KEYS

# A key name that suggests a secret. "secret_store" and "upn" are allowed above;
# everything else matching this is refused.
SECRET_KEY = re.compile(
    r"(?i)(pass(word|wd|phrase)?|secret|token|cookie|private|credential|session"
    r"|bearer|auth|otp|totp|pin|api[_-]?key|(^|_)key($|_))"
)


def default_config_path(environ: Mapping[str, str] | None = None) -> Path:
    """``$CRIMSON_HEADLESS_PASSKEY_CONFIG``, else ``$XDG_CONFIG_HOME``, else ``~/.config``."""
    env = os.environ if environ is None else environ
    # The override is read from both, so a test that passes its own environ
    # dict can never fall through to the real ~/.config.
    override = env.get(ENV_CONFIG) or os.environ.get(ENV_CONFIG)
    if override:
        return Path(override).expanduser()
    xdg = env.get("XDG_CONFIG_HOME") or os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / CONFIG_DIRNAME / CONFIG_FILENAME


def _looks_secret(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 16:
        return False
    return redact.redact_text(value) != value


def load_user_config(path: Path | None = None, *, warn: Any = None) -> dict[str, Any]:
    """The validated settings in the config file, or {} when there is none.

    Raises ConfigError for a secret-looking key or value, or a file someone else
    can write. Unknown non-secret keys produce a warning and are ignored.
    """
    warn = warn or (lambda msg: print(f"warning: {msg}", file=sys.stderr))
    path = path or default_config_path()
    if not path.is_file():
        return {}
    check_env_file(path)  # same rule as .env: ours, and nobody else can write it
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e

    config: dict[str, Any] = {}
    for key, value in data.items():
        if key not in ALLOWED_KEYS and SECRET_KEY.search(key):
            raise ConfigError(
                f"{path}: {key!r} looks like a secret. The config file holds non-secret "
                "settings only; secrets belong in the keychain. Remove it."
            )
        if isinstance(value, dict):
            warn(f"{path}: ignoring table [{key}] (only top-level settings are read)")
            continue
        values = value if isinstance(value, list) else [value]
        if any(_looks_secret(v) for v in values):
            raise ConfigError(
                f"{path}: the value of {key!r} looks like a token or key. The config file "
                "holds non-secret settings only. Remove it."
            )
        if key not in ALLOWED_KEYS:
            warn(f"{path}: ignoring unknown setting {key!r}")
            continue
        config[key] = value
    return config


def as_env(config: Mapping[str, Any]) -> dict[str, str]:
    """The settings part of a config as CRIMSON_HEADLESS_PASSKEY_* variables."""
    env: dict[str, str] = {}
    for key, var in SETTING_KEYS.items():
        if key not in config:
            continue
        value = config[key]
        env[var] = ",".join(map(str, value)) if isinstance(value, list) else str(value)
    return env


def command_defaults(config: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in config.items() if k in DEFAULT_KEYS}
