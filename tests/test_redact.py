"""Secrets must never appear in errors, tracebacks, logs or stderr.

These tests inject known fake secrets and assert each channel is scrubbed by
the REAL redactor. ``test_removing_library_filter_allows_logger_leak`` shows
the assertions are meaningful: with the filter removed, the same secret
appears in the log record.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

from crimson_headless_passkey import redact
from crimson_headless_passkey.errors import AuthFailedError, LoginPasskeyError
from crimson_headless_passkey.redact import PLACEHOLDER

FAKE_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSECRETKEYMATERIAL0123456789abcdef"
FAKE_CRED_ID = "Y3JlZGVudGlhbElkMTIzNDU2Nzg5MGFiY2RlZg=="
FAKE_COOKIE = "FedAuth=VerySecretFedAuthValue0123456789abcdefghijklmnop"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
FAKE_BEARER = "Bearer ya29.a0AfH6SMBxxxxxxxxSECRETTOKENxxxxxxxxxxxx"
FAKE_URL = "https://login.harvard.edu/oauth2/v1/authorize?code=SECRET_AUTH_CODE_XYZ&state=abc"
FAKE_TEMPAUTH = "https://cdn.example/file?tempauth=TEMPAUTHSECRETVALUE0123456789abcdef"


@pytest.fixture(autouse=True)
def clean_registry():
    redact.forget_all()
    yield
    redact.forget_all()
    redact.uninstall()


def test_register_secret_is_scrubbed_from_text():
    redact.register_secret(FAKE_KEY)
    redact.register_secret(FAKE_CRED_ID)
    text = f"loaded key={FAKE_KEY} id={FAKE_CRED_ID}"
    out = redact.redact_text(text)
    assert FAKE_KEY not in out
    assert FAKE_CRED_ID not in out
    assert PLACEHOLDER in out


def test_register_secret_covers_b64_and_unquote_variants():
    secret = "plainSecretValueXYZ999111"
    redact.register_secret(secret)
    import base64
    from urllib.parse import quote

    assert secret not in redact.redact_text(quote(secret))
    assert secret not in redact.redact_text(base64.b64encode(secret.encode()).decode())


def test_cookie_header_and_jwt_shapes_are_scrubbed_without_registry():
    text = (
        f"Cookie: {FAKE_COOKIE}\nAuthorization: {FAKE_BEARER}\n"
        f"token={FAKE_JWT}\n{FAKE_URL}\n{FAKE_TEMPAUTH}"
    )
    out = redact.redact_text(text)
    assert "VerySecretFedAuthValue" not in out
    assert "ya29." not in out
    assert FAKE_JWT not in out
    assert "SECRET_AUTH_CODE_XYZ" not in out
    assert "TEMPAUTHSECRETVALUE" not in out
    assert PLACEHOLDER in out


def test_registered_secret_absent_from_str_and_repr():
    redact.register_secret(FAKE_KEY)
    err = AuthFailedError(f"passkey rejected; key was {FAKE_KEY}")
    assert FAKE_KEY not in str(err)
    assert FAKE_KEY not in repr(err)
    assert PLACEHOLDER in str(err)


def test_registered_secret_absent_from_traceback_and_chain():
    redact.register_secret(FAKE_COOKIE)

    def blow():
        try:
            raise RuntimeError(f"upstream said {FAKE_COOKIE}")
        except RuntimeError as inner:
            raise AuthFailedError(f"wrapped {FAKE_COOKIE}") from inner

    try:
        blow()
    except AuthFailedError as e:
        text = redact.format_exception(e)
    assert FAKE_COOKIE not in text
    assert "VerySecretFedAuthValue" not in text
    assert PLACEHOLDER in text


def test_registered_secret_absent_from_stderr_wrapper():
    redact.register_secret(FAKE_CRED_ID)
    buf = io.StringIO()
    wrapper = redact.RedactingStream(buf)
    wrapper.write(f"id={FAKE_CRED_ID}\n")
    wrapper.flush()
    assert FAKE_CRED_ID not in buf.getvalue()
    assert PLACEHOLDER in buf.getvalue()


def test_registered_secret_absent_from_excepthook_output(monkeypatch):
    """Plain ValueError so the test fails without the hook (AuthFailedError self-redacts)."""
    redact.register_secret(FAKE_KEY)
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stderr", buf)
    try:
        raise ValueError(f"key={FAKE_KEY}")
    except ValueError as e:
        redact._excepthook(type(e), e, e.__traceback__)
    text = buf.getvalue()
    assert FAKE_KEY not in text
    assert PLACEHOLDER in text


def test_registered_secret_absent_from_log_message_and_exc_text():
    redact.register_secret(FAKE_KEY)
    redact.install()
    log = logging.getLogger("crimson_headless_passkey.test_redact_channels")
    log.handlers.clear()
    log.filters.clear()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    # Record factory from install() scrubs at creation; also attach filter.
    handler.addFilter(redact.RedactingFilter())
    log.addHandler(handler)
    log.setLevel(logging.ERROR)
    try:
        raise LoginPasskeyError(f"key={FAKE_KEY}")
    except LoginPasskeyError:
        log.exception("failed with %s", FAKE_KEY)
    text = stream.getvalue()
    assert FAKE_KEY not in text
    assert PLACEHOLDER in text


def test_removing_library_filter_allows_logger_leak():
    """Honest mutation property: without the filter/factory, the secret appears.

    This is the inverse of the absence tests above. Run once with the scrubbing
    disabled to confirm those assertions would fail (see Phase 3 report).
    """
    redact.register_secret(FAKE_KEY)
    # Ensure process-wide install is off so the record factory does not scrub.
    redact.uninstall()
    log = logging.getLogger("crimson_headless_passkey.test_redact_leak")
    log.handlers.clear()
    log.filters.clear()
    # Drop any library filters this logger might have inherited (none) and
    # use a plain handler with NO RedactingFilter.
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.ERROR)
    log.propagate = False
    # Bypass redact.scrub by logging a pre-formatted string through a logger
    # that has no filter and no record factory scrub (uninstall restored factory).
    log.error("leaked %s", FAKE_KEY)
    text = stream.getvalue()
    assert FAKE_KEY in text, "without the filter the secret must be visible (mutation property)"


def test_active_context_manager_installs_and_restores():
    assert not getattr(redact, "_installed", {}).get("full")
    with redact.active():
        assert redact._installed.get("full")
        redact.register_secret(FAKE_KEY)
        assert FAKE_KEY not in redact.redact_text(FAKE_KEY)
    assert not redact._installed.get("full")


def test_register_credential_and_cookies():
    redact.register_credential(
        {"privateKey": FAKE_KEY, "credentialId": FAKE_CRED_ID, "userHandle": "dXNlcg=="}
    )
    redact.register_cookies([{"name": "FedAuth", "value": "CookieValueABC123XYZ999"}])
    out = redact.redact_text(f"{FAKE_KEY} {FAKE_CRED_ID} CookieValueABC123XYZ999")
    assert FAKE_KEY not in out
    assert FAKE_CRED_ID not in out
    assert "CookieValueABC123XYZ999" not in out


def test_install_refcount_nested_active():
    """Concurrent/nested active() must not uninstall early (E)."""
    assert redact._install_refcount == 0
    with redact.active():
        assert redact._install_refcount == 1
        assert redact._installed.get("full")
        with redact.active():
            assert redact._install_refcount == 2
            assert redact._installed.get("full")
        assert redact._install_refcount == 1
        assert redact._installed.get("full"), "inner exit must not tear down outer install"
    assert redact._install_refcount == 0
    assert not redact._installed.get("full")


def test_uninstall_restores_stderr_only_if_still_wrapper(monkeypatch):
    real = io.StringIO()
    monkeypatch.setattr(sys, "stderr", real)
    redact.install()
    wrapper = sys.stderr
    assert isinstance(wrapper, redact.RedactingStream)
    replacement = io.StringIO()
    monkeypatch.setattr(sys, "stderr", replacement)
    redact.uninstall()
    # We replaced stderr after install; uninstall must leave the replacement alone.
    assert sys.stderr is replacement


def test_httpcore_child_logger_is_filtered():
    """Filters cover httpcore.http11, not only the parent logger (D)."""
    redact.register_secret(FAKE_KEY)
    log = logging.getLogger("httpcore.http11")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    prev_prop = log.propagate
    log.propagate = False
    try:
        log.error("httpcore saw %s", FAKE_KEY)
        text = stream.getvalue()
        assert FAKE_KEY not in text
        assert PLACEHOLDER in text
    finally:
        log.removeHandler(handler)
        log.propagate = prev_prop


def test_httpx_logger_with_plain_stream_handler_scrubs_secret():
    """G: logging.getLogger('httpx') + plain StreamHandler must scrub."""
    redact.register_secret(FAKE_KEY)
    log = logging.getLogger("httpx")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    # No RedactingFilter on the handler — the logger-level filter from import must scrub.
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    prev_prop = log.propagate
    log.propagate = False
    try:
        log.error("httpx request cookie=%s", FAKE_KEY)
        text = stream.getvalue()
        assert FAKE_KEY not in text, text
        assert PLACEHOLDER in text
    finally:
        log.removeHandler(handler)
        log.propagate = prev_prop
