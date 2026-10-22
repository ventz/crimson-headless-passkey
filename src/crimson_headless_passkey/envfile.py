"""Read settings from a ``.env`` file.

Only ``CRIMSON_HEADLESS_PASSKEY_*`` keys are used, so a ``.env`` shared with
other tools is fine. Real environment variables win over the file.

The file decides which hosts receive your username and where the private key
is read from, so it gets the same ownership rule as the data directory: it
must belong to you and nobody else may write to it.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from pathlib import Path

from .errors import ConfigError, InsecurePermissionsError

PREFIX = "CRIMSON_HEADLESS_PASSKEY_"
DEFAULT_ENV_FILE = Path(".env")


def parse_env(text: str, source: str = ".env") -> dict[str, str]:
    """Parse ``KEY=value`` lines.

    Supported: blank lines, ``#`` comments, an optional ``export`` prefix,
    single- or double-quoted values (taken literally), and `` #`` comments
    after unquoted values. No variable expansion.
    """
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key or not key.replace("_", "").isalnum():
            raise ConfigError(f"{source}:{number}: expected KEY=value")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def check_env_file(path: Path) -> None:
    """Refuse a file someone else owns or can write to."""
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{path} is not a regular file")
    if os.name != "posix":
        return
    if st.st_uid != os.getuid():
        raise InsecurePermissionsError(f"{path} is not owned by the current user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise InsecurePermissionsError(
            f"{path} is writable by other users (mode {stat.filemode(st.st_mode)}). "
            f"Fix with: chmod go-w {path}"
        )


def load_env_file(path: Path) -> dict[str, str]:
    """This tool's settings from ``path``; other keys are ignored."""
    check_env_file(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    return {k: v for k, v in parse_env(text, str(path)).items() if k.startswith(PREFIX)}


def merged_env(
    env_file: Path | None = None,
    environ: Mapping[str, str] = os.environ,
    *,
    config_file: Path | None = None,
    use_config: bool = True,
) -> dict[str, str]:
    """The environment with ``.env`` and the user config file filled in underneath it.

    Precedence: real environment > ``.env`` > ``config.toml`` (see
    ``userconfig``). ``env_file`` must exist when given explicitly. Without it,
    ``./.env`` is used if present.
    """
    from . import userconfig  # late: userconfig imports this module

    layers: dict[str, str] = {}
    if use_config:
        layers.update(userconfig.as_env(userconfig.load_user_config(config_file)))
    if env_file is not None:
        if not env_file.exists():
            raise ConfigError(f"{env_file} not found")
        layers.update(load_env_file(env_file))
    elif DEFAULT_ENV_FILE.is_file():
        layers.update(load_env_file(DEFAULT_ENV_FILE))
    return {**layers, **environ}
