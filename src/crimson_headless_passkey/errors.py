"""Exceptions the CLI reports as a one-line error instead of a traceback.

Every exception here renders its message through ``redact.redact_text`` (see
``__str__``), so a cookie, token, key or credential ID that ends up in a message
is scrubbed wherever the exception is printed: the CLI's one-line error, a
traceback, or a log record. Each class also carries the ``status`` and process
``exit_code`` the CLI reports for it (see ``exitcodes``).
"""

from __future__ import annotations

from . import exitcodes, redact


class LoginPasskeyError(Exception):
    """Base class for expected, user-facing failures. Defaults to a config error (2)."""

    status = exitcodes.STATUS_CONFIG
    exit_code = exitcodes.EXIT_CONFIG

    def __str__(self) -> str:
        # Redact at render time, not construction, so a secret registered
        # after the exception was built is still caught.
        return redact.redact_text(super().__str__())

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r})"


class ConfigError(LoginPasskeyError):
    """A setting, the .env file or the user config file is invalid."""


class RefusedURLError(ConfigError):
    """The URL is one this command must never touch (e.g. PeopleSoft for fetch)."""


class CredentialFileError(LoginPasskeyError):
    """The credential or auth-state file is missing or malformed."""


class KeychainError(LoginPasskeyError):
    """The OS keychain could not store or return the private key."""


class InsecurePermissionsError(LoginPasskeyError):
    """A secret file can be read by other users."""


class RegistrationError(LoginPasskeyError):
    """Registration could not start or did not capture a credential."""


class AuthFailedError(LoginPasskeyError):
    """Sign-in was attempted and did not succeed: passkey rejected, Okta error, timeout."""

    status = exitcodes.STATUS_AUTH_FAILED
    exit_code = exitcodes.EXIT_AUTH_FAILED


class NeedsHumanError(LoginPasskeyError):
    """A step only a person can do: no passkey option, push/number challenge, CAPTCHA."""

    status = exitcodes.STATUS_NEEDS_HUMAN
    exit_code = exitcodes.EXIT_NEEDS_HUMAN


class NetworkError(LoginPasskeyError):
    """The IdP or target was unreachable, or kept failing after retries."""

    status = exitcodes.STATUS_NETWORK
    exit_code = exitcodes.EXIT_NETWORK


class NotFoundError(LoginPasskeyError):
    """The item does not exist, or the signed-in account may not see it."""

    status = exitcodes.STATUS_NOT_FOUND
    exit_code = exitcodes.EXIT_NOT_FOUND


ERRORS_BY_STATUS: dict[str, type[LoginPasskeyError]] = {
    exitcodes.STATUS_AUTH_FAILED: AuthFailedError,
    exitcodes.STATUS_NEEDS_HUMAN: NeedsHumanError,
    exitcodes.STATUS_NETWORK: NetworkError,
    exitcodes.STATUS_NOT_FOUND: NotFoundError,
    exitcodes.STATUS_CONFIG: ConfigError,
}


def error_for_status(status: str, reason: str | None) -> LoginPasskeyError:
    """The exception that represents a failed sign-in with this status."""
    cls = ERRORS_BY_STATUS.get(status, AuthFailedError)
    return cls(reason or status)
