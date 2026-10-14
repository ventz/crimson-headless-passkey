"""Settings: defaults, environment variables and URL helpers."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .secretstore import default_secret_store, parse_secret_store

DEFAULT_LOGIN_URL = "https://login.harvard.edu"
DEFAULT_RP_ID = "login.harvard.edu"
DEFAULT_IDP_HOSTS = ("login.harvard.edu", "harvard.okta.com")

ENV_HOME = "CRIMSON_HEADLESS_PASSKEY_HOME"
ENV_LOGIN_URL = "CRIMSON_HEADLESS_PASSKEY_URL"
ENV_RP_ID = "CRIMSON_HEADLESS_PASSKEY_RP_ID"
ENV_IDP_HOSTS = "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS"
ENV_USERNAME = "CRIMSON_HEADLESS_PASSKEY_USERNAME"
ENV_SECRET_STORE = "CRIMSON_HEADLESS_PASSKEY_SECRET_STORE"

# Okta's own signed-in pages. Landing on one of these means sign-in finished
# even though the page is still on an IdP host (e.g. when the target URL is the
# IdP itself). /account-settings/ is what login.harvard.edu shows (seen
# 2026-10-03); the other two are Okta's classic and end-user dashboards.
OKTA_SIGNED_IN_PATHS = ("/account-settings/", "/enduser/", "/app/UserHome")

CREDENTIAL_FILENAME = "passkey_credential.json"
AUTH_STATE_FILENAME = "auth_state.json"


def default_data_dir(env: Mapping[str, str] = os.environ) -> Path:
    """Where secrets live.

    $CRIMSON_HEADLESS_PASSKEY_HOME, else $XDG_DATA_HOME/crimson-headless-passkey
    (~/.local/share/crimson-headless-passkey when XDG_DATA_HOME is unset).
    """
    if home := env.get(ENV_HOME):
        return Path(home).expanduser()
    xdg = env.get("XDG_DATA_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
    return base / "crimson-headless-passkey"


def parse_hosts(value: str) -> tuple[str, ...]:
    """Split a comma-separated host list, normalized to lowercase."""
    return tuple(h.strip().lower() for h in value.split(",") if h.strip())


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def is_idp_url(url: str, idp_hosts: Iterable[str]) -> bool:
    """True when the URL's host is one of the identity-provider hosts.

    Compares the parsed hostname exactly, so an IdP host that only appears in
    a query string (e.g. a ``redirect_uri``) does not count.
    """
    return host_of(url) in {h.lower() for h in idp_hosts}


LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def is_secure_url(url: str) -> bool:
    """https, or http on loopback only (for local testing)."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and (parts.hostname or "") in LOOPBACK_HOSTS


def on_signed_in_path(path: str) -> bool:
    """Match OKTA_SIGNED_IN_PATHS on whole path segments (/app/UserHomeX does not count)."""
    for prefix in OKTA_SIGNED_IN_PATHS:
        base = prefix.rstrip("/")
        if path == base or path.startswith(base + "/"):
            return True
    return False


def is_signed_in_url(url: str, idp_hosts: Iterable[str]) -> bool:
    """True when the URL looks like a destination: a secure page that is off the
    IdP, or one of the IdP's own signed-in pages.

    This is necessary but not sufficient. The caller also needs evidence that a
    sign-in happened (see ``flows.wait_for_sign_in``): an app's page before its
    redirect to the IdP looks exactly the same.
    """
    if not is_secure_url(url):
        return False  # about:blank, chrome-error://, plain http and similar
    if not is_idp_url(url, idp_hosts):
        return True
    return on_signed_in_path(urlsplit(url).path)


def redact_url(url: str) -> str:
    """scheme://host/path only: query strings and fragments can carry OAuth codes and tokens."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url.split("?", 1)[0].split("#", 1)[0]
    redacted = f"{parts.scheme}://{parts.netloc}{parts.path}"
    if parts.query or parts.fragment:
        redacted += " (query/fragment hidden)"
    return redacted


# Terminal escape sequences: CSI (colors, ``ESC [ 31 m``), OSC (``ESC ] ... BEL``,
# e.g. terminal hyperlinks) and two-byte escapes. A URL copied from colored
# output (``aws sso login``, ``ls --color``) can carry them (seen 2026-10-14).
ANSI_ESCAPE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC, ended by BEL or ST
    r"|\x1b[@-Z\\-_]"  # other two-byte escapes
    r"|\x9b[0-?]*[ -/]*[@-~]"  # 8-bit CSI
)
CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f\s]")


def clean_url(url: str) -> str:
    """Remove terminal color codes, control characters and all whitespace.

    A real URL never contains raw whitespace, so a URL that wrapped across
    lines when it was pasted is joined back together.
    """
    return CONTROL_OR_SPACE.sub("", ANSI_ESCAPE.sub("", url))


def final_url_problem(url: str) -> str | None:
    """Why ``url`` cannot be where a successful sign-in ended, or None if it can.

    The browser's own error page (``chrome-error://chromewebdata/``) and any
    other non-http(s) page (about:blank, data:, file:) are never success,
    however sign-in got there (CLAUDE.md constraint 5; a 2026-10-14 AWS run
    printed "Signed in" on chrome-error after a script redirect failed).
    """
    if url.startswith("chrome-error://"):
        return "the page failed to load (the browser is showing its error page)"
    if urlsplit(url).scheme not in ("http", "https"):
        return f"the page ended on a non-web URL ({redact_url(url)})"
    return None


def validate_url(url: str) -> str:
    """Clean pasted junk, then accept https URLs, and http only on loopback."""
    url = clean_url(url)
    if not is_secure_url(url):
        raise ValueError(f"not an https URL: {url!r}")
    return url


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    login_url: str
    rp_id: str
    idp_hosts: tuple[str, ...]
    username: str | None = None
    # Where the private key is kept: "keychain" (default on macOS) or "file".
    secret_store: str = field(default_factory=default_secret_store)

    @property
    def credential_file(self) -> Path:
        return self.data_dir / CREDENTIAL_FILENAME

    @property
    def auth_state_file(self) -> Path:
        return self.data_dir / AUTH_STATE_FILENAME

    @classmethod
    def from_env(
        cls,
        *,
        data_dir: Path | str | None = None,
        login_url: str | None = None,
        rp_id: str | None = None,
        idp_hosts: Iterable[str] | None = None,
        username: str | None = None,
        secret_store: str | None = None,
        env: Mapping[str, str] = os.environ,
    ) -> Settings:
        """Build settings: explicit arguments win, then env vars, then defaults."""
        if idp_hosts is not None:
            hosts = tuple(h.lower() for h in idp_hosts)
        elif env.get(ENV_IDP_HOSTS):
            hosts = parse_hosts(env[ENV_IDP_HOSTS])
        else:
            hosts = DEFAULT_IDP_HOSTS
        return cls(
            data_dir=(
                Path(data_dir).expanduser() if data_dir else default_data_dir(env)
            ).absolute(),
            login_url=validate_url(login_url or env.get(ENV_LOGIN_URL) or DEFAULT_LOGIN_URL),
            rp_id=(rp_id or env.get(ENV_RP_ID) or DEFAULT_RP_ID).lower(),
            idp_hosts=hosts,
            username=username or env.get(ENV_USERNAME) or None,
            secret_store=parse_secret_store(
                secret_store or env.get(ENV_SECRET_STORE) or default_secret_store()
            ),
        )
