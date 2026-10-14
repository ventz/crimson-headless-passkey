"""Exceptions the CLI reports as a one-line error instead of a traceback."""


class LoginPasskeyError(Exception):
    """Base class for expected, user-facing failures."""


class ConfigError(LoginPasskeyError):
    """A setting or the .env file is invalid."""


class CredentialFileError(LoginPasskeyError):
    """The credential or auth-state file is missing or malformed."""


class KeychainError(LoginPasskeyError):
    """The OS keychain could not store or return the private key."""


class InsecurePermissionsError(LoginPasskeyError):
    """A secret file can be read by other users."""


class RegistrationError(LoginPasskeyError):
    """Registration could not start or did not capture a credential."""
