"""Scrub secrets out of text before it reaches stderr, logs, tracebacks or exceptions.

Two layers, both applied by ``redact_text``:

1. **Known values.** Every secret the tool handles at runtime (the private key,
   credential IDs, user handles, Keychain values, cookie values) is registered
   with ``register_secret`` the moment it is loaded or exported. Any exact
   occurrence, and its URL-encoded and base64url forms, is replaced. This is
   what makes short secrets safe: a pattern cannot recognize a 16-character
   credential ID, but the registry can.
2. **Shapes.** Secrets the tool never saw (a token in a server error, a header
   echoed by httpx) are caught by pattern: Cookie/Set-Cookie/Authorization
   values, ``name=value`` pairs for session/token names, JWTs, PEM blocks, URL
   query strings and fragments, and long opaque base64/hex runs.

This module imports nothing from the package, so ``errors`` can use it without
an import cycle. Callers reach it as ``redact.redact_text`` (an attribute
lookup, not a bound import) so the tests can prove that turning it off leaks.
"""

from __future__ import annotations

import base64
import contextlib
import logging
import re
import sys
import threading
import traceback
from collections.abc import Iterable, Mapping
from typing import Any, TextIO
from urllib.parse import quote, quote_plus, unquote, unquote_plus

PLACEHOLDER = "[REDACTED]"

# Shorter values are too likely to collide with ordinary words; nothing the
# tool registers (keys, credential IDs, cookie values) is this short.
MIN_SECRET_LEN = 6

_lock = threading.Lock()
_SECRETS: set[str] = set()


def register_secret(value: Any) -> None:
    """Remember a secret value so every later ``redact_text`` call removes it."""
    if not isinstance(value, str):
        return
    value = value.strip()
    if len(value) < MIN_SECRET_LEN:
        return
    variants = {
        value,
        quote(value, safe=""),
        quote_plus(value),
        unquote(value),
        unquote_plus(value),
    }
    # CDP gives credential IDs as standard base64; a page sees base64url.
    variants.add(value.replace("+", "-").replace("/", "_").rstrip("="))
    with contextlib.suppress(Exception):
        variants.add(base64.b64encode(value.encode("utf-8")).decode("ascii"))
    with contextlib.suppress(Exception):
        variants.add(base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("="))
    with _lock:
        _SECRETS.update(v for v in variants if len(v) >= MIN_SECRET_LEN)


def register_secrets(values: Iterable[Any]) -> None:
    for value in values:
        register_secret(value)


def register_credential(cred: Mapping[str, Any]) -> None:
    """Register a WebAuthn credential's secret and identifying fields."""
    for field in ("privateKey", "credentialId", "userHandle"):
        register_secret(cred.get(field))
    key = cred.get("privateKey")
    if isinstance(key, str):
        # The raw key bytes can also surface re-encoded (e.g. hex in a CDP dump).
        with contextlib.suppress(ValueError, TypeError):
            register_secret(base64.b64decode(key, validate=False).hex())


def register_cookies(cookies: Iterable[Mapping[str, Any]]) -> None:
    """Register every cookie value in a Playwright cookie list or storage state."""
    for cookie in cookies:
        register_secret(cookie.get("value"))


def register_storage_state(state: Mapping[str, Any] | None) -> None:
    if not state:
        return
    register_cookies(state.get("cookies", []) or [])
    for origin in state.get("origins", []) or []:
        for item in origin.get("localStorage", []) or []:
            register_secret(item.get("value"))


def forget_all() -> None:
    """Clear the registry (tests only)."""
    with _lock:
        _SECRETS.clear()


# --- shape patterns -----------------------------------------------------------

# Header-style secrets: everything after the separator to the end of the line.
_HEADER = re.compile(
    r"(?im)\b(set-cookie|cookie|authorization|proxy-authorization|x-requestdigest"
    r"|x-api-key|x-auth-token)(['\"]?\s*[:=]\s*)(?!\[REDACTED\])[^\r\n]+"
)
# name=value pairs whose name marks a session or token (cookies, query, form).
# `code=` followed by a short number on its own is our exit-code status line,
# not an OAuth code, so it is left alone.
_PAIR = re.compile(
    r"(?i)\b(FedAuth|rtFa|SPOIDCRL|EdgeAccessCookie|sid|idx|DT|JSESSIONID"
    r"|ASP\.NET_SessionId|ESTSAUTH\w*|SignInStateCookie|buid|fpc|esctx\w*|xids"
    r"|okta-oauth-\w+|proximity_\w+|PS_TOKEN|access_token|id_token|refresh_token"
    r"|client_secret|code(?!=\d{1,3}(?!\S))|state|password|passwd|pwd|api[_-]?key|token|secret"
    r"|tempauth|access_key|sig|signature|shared_access_token"
    r"|\w*session\w*|\w*token\w*)=(?!\[REDACTED\])[^\s&;,'\"<>]+"
)
# JSON / repr / kwargs style: "privateKey": "...", value='...'.
_KEYED = re.compile(
    r"(?i)(['\"]?\b(?:privateKey|private_key|credentialId|credential_id|userHandle"
    r"|user_handle|value|password|passwd|secret|token|access_token|id_token"
    r"|refresh_token|client_secret|cookie|cookies)\b['\"]?\s*[:=]\s*)(['\"])"
    r"(?!\[REDACTED\])((?:\\.|(?!\2).)+)\2"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----")
# Query strings and fragments can carry OAuth codes and tokens of any name.
_URL_TAIL = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s?#'\"<>]*)[?#][^\s'\"<>]*", re.IGNORECASE)
_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
# Opaque runs: standard base64 (may contain '/') and base64url.
_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_B64URL = re.compile(r"[A-Za-z0-9_-]{32,}")


def _looks_random(s: str) -> bool:
    """Mixed case and digits: true for keys and tokens, false for words and test names."""
    digits = sum(c.isdigit() for c in s)
    upper = sum(c.isupper() for c in s)
    lower = sum(c.islower() for c in s)
    return digits >= 2 and upper >= 2 and lower >= 2


def _b64_run(m: re.Match[str]) -> str:
    s = m.group(0)
    # Paths are '/'-dense (a '/' every few characters); base64 has one in ~64.
    if s.count("/") * 16 > len(s):
        return s
    if "+" in s or s.endswith("=") or _looks_random(s):
        return PLACEHOLDER
    return s


def _b64url_run(m: re.Match[str]) -> str:
    s = m.group(0)
    return PLACEHOLDER if _looks_random(s) else s


def redact_text(text: Any) -> str:
    """Return ``text`` with every known secret and secret-shaped substring replaced."""
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    with _lock:
        known = sorted(_SECRETS, key=len, reverse=True)
    for secret in known:  # longest first, so a value's prefix never survives
        if secret in text:
            text = text.replace(secret, PLACEHOLDER)
    text = _PEM.sub(PLACEHOLDER, text)
    text = _HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}", text)
    text = _KEYED.sub(lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}{m.group(2)}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {PLACEHOLDER}", text)
    text = _JWT.sub(PLACEHOLDER, text)
    text = _URL_TAIL.sub(lambda m: f"{m.group(1)}?{PLACEHOLDER}", text)
    text = _PAIR.sub(lambda m: f"{m.group(1)}={PLACEHOLDER}", text)
    text = _HEX.sub(PLACEHOLDER, text)
    text = _B64.sub(_b64_run, text)
    text = _B64URL.sub(_b64url_run, text)
    return text


def format_exception(exc: BaseException) -> str:
    """A full traceback (chained causes included) with secrets removed."""
    raw = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return redact.redact_text(raw)


# --- output wiring ------------------------------------------------------------


class RedactingFilter(logging.Filter):
    """Rewrite a record's message and traceback text with secrets removed."""

    def filter(self, record: logging.LogRecord) -> bool:
        scrub(record)
        return True


def scrub(record: logging.LogRecord) -> logging.LogRecord:
    try:
        message = record.getMessage()
    except Exception:  # a bad format string must not crash logging
        message = str(record.msg)
    record.msg = redact.redact_text(message)
    record.args = ()
    if record.exc_info and record.exc_info[1] is not None:
        record.exc_text = format_exception(record.exc_info[1])
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = redact.redact_text(record.exc_text)
    if record.stack_info:
        record.stack_info = redact.redact_text(record.stack_info)
    return record


class RedactingStream:
    """A text stream wrapper that redacts each complete line before writing it.

    Lines are buffered until their newline so a secret split across two
    ``write`` calls is still seen whole. ``flush`` writes any partial line.
    """

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream
        self._buffer = ""

    def write(self, data: str) -> int:
        self._buffer += data
        if "\n" in self._buffer:
            complete, self._buffer = self._buffer.rsplit("\n", 1)
            self._stream.write(redact.redact_text(complete) + "\n")
        return len(data)

    def flush(self) -> None:
        if self._buffer:
            self._stream.write(redact.redact_text(self._buffer))
            self._buffer = ""
        self._stream.flush()

    def isatty(self) -> bool:
        return self._stream.isatty()

    def fileno(self) -> int:
        return self._stream.fileno()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


_installed: dict[str, Any] = {}


def _record_factory(old: Any) -> Any:
    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        return scrub(old(*args, **kwargs))

    return factory


def _excepthook(exc_type: Any, exc: BaseException, tb: Any) -> None:
    exc.__traceback__ = tb
    sys.stderr.write(format_exception(exc))
    sys.stderr.flush()


# Parent loggers plus httpcore's child loggers (records often go there directly).
_LIBRARY_LOGGERS = (
    "httpx",
    "httpcore",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.connection",
    "httpcore.connection_pool",
    "httpcore.proxy",
    "playwright",
    "asyncio",
)
_library_filters: list[tuple[logging.Logger, RedactingFilter]] = []
_install_refcount = 0
_refcount_lock = threading.Lock()


def attach_library_filters() -> None:
    """Attach a ``RedactingFilter`` to httpx / httpcore (+ children) / playwright.

    Called at package import so library/bot callers get scrubbing even when
    they never call ``install()``. Idempotent. Child loggers are listed
    explicitly because a filter on ``httpcore`` alone does not run for
    ``httpcore.http11`` records that have their own handlers.
    """
    if _library_filters:
        return
    for name in _LIBRARY_LOGGERS:
        logger = logging.getLogger(name)
        filt = RedactingFilter()
        logger.addFilter(filt)
        _library_filters.append((logger, filt))


def install() -> None:
    """Redact stderr, uncaught tracebacks and every log record in this process.

    Reference-counted: concurrent ``signed_in`` / ``fetch`` / ``active()``
    callers share one install; ``uninstall()`` only tears down when the last
    reference drops. Prefer ``active()`` in library code. See SECURITY.md.
    """
    global _install_refcount
    attach_library_filters()
    with _refcount_lock:
        _install_refcount += 1
        if _installed.get("full"):
            return
        _installed["stderr"] = sys.stderr
        _installed["excepthook"] = sys.excepthook
        _installed["factory"] = logging.getLogRecordFactory()
        _installed["wrapper"] = RedactingStream(sys.stderr)
        sys.stderr = _installed["wrapper"]  # type: ignore[assignment]
        sys.excepthook = _excepthook
        logging.setLogRecordFactory(_record_factory(_installed["factory"]))
        _installed["full"] = True


def uninstall() -> None:
    """Drop one ``install()`` reference; restore streams only at refcount zero.

    Restores stderr only when it is still our ``RedactingStream`` wrapper (so a
    caller that replaced stderr after ``install`` is left alone). Library logger
    filters from import stay attached.
    """
    global _install_refcount
    with _refcount_lock:
        if _install_refcount > 0:
            _install_refcount -= 1
        if _install_refcount > 0:
            return
        if not _installed.get("full"):
            _installed.clear()
            return
        with_flush = sys.stderr
        if isinstance(with_flush, RedactingStream):
            with_flush.flush()
        # Only restore stderr if it is still our wrapper.
        if sys.stderr is _installed.get("wrapper"):
            sys.stderr = _installed["stderr"]
        sys.excepthook = _installed["excepthook"]
        logging.setLogRecordFactory(_installed["factory"])
        _installed.clear()


@contextlib.contextmanager
def active() -> Any:
    """Install redaction for a block; refcounted so nested/concurrent use is safe.

    Use this (or rely on ``signed_in`` / ``fetch``, which call it) from bots and
    library callers. Nested and overlapping ``active()`` / ``install()`` pairs
    share one process-wide install; only the last exit uninstalls.
    """
    install()
    try:
        yield
    finally:
        uninstall()


def scrubbed_exception(exc: BaseException) -> BaseException:
    """Return ``exc`` with its message rewritten through ``redact_text``.

    Used when wrapping httpx / Playwright errors before they leave the public
    API, so ``str(exc)`` / ``repr(exc)`` never carry a cookie or token.
    """
    msg = redact.redact_text(str(exc))
    with contextlib.suppress(Exception):
        exc.args = (msg, *exc.args[1:])
    return exc


# Self-reference so module-internal calls go through the attribute.
redact = sys.modules[__name__]
attach_library_filters()
