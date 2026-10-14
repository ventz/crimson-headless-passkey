"""Automated passkey sign-in for Okta through a CDP virtual authenticator."""

from importlib.metadata import PackageNotFoundError, version

from .authenticator import VirtualAuthenticator
from .config import Settings
from .envfile import merged_env
from .errors import (
    ConfigError,
    CredentialFileError,
    InsecurePermissionsError,
    LoginPasskeyError,
    RegistrationError,
)
from .flows import LoginResult, authenticate

try:
    __version__ = version("crimson-headless-passkey")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0"

__all__ = [
    "ConfigError",
    "CredentialFileError",
    "InsecurePermissionsError",
    "LoginPasskeyError",
    "LoginResult",
    "RegistrationError",
    "Settings",
    "VirtualAuthenticator",
    "authenticate",
    "merged_env",
]
