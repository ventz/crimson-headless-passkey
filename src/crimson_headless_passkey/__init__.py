"""Automated passkey sign-in for Okta through a CDP virtual authenticator."""

from importlib.metadata import PackageNotFoundError, version

from .authenticator import VirtualAuthenticator
from .config import Settings
from .downloader import FetchReport, fetch, fetch_sync
from .envfile import merged_env
from .errors import (
    AuthFailedError,
    ConfigError,
    CredentialFileError,
    InsecurePermissionsError,
    LoginPasskeyError,
    NeedsHumanError,
    NetworkError,
    NotFoundError,
    RefusedURLError,
    RegistrationError,
)
from .flows import LoginResult, authenticate
from .session import SignedIn, http_client, save_cookies, signed_in

try:
    __version__ = version("crimson-headless-passkey")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0"

__all__ = [
    "AuthFailedError",
    "ConfigError",
    "CredentialFileError",
    "FetchReport",
    "InsecurePermissionsError",
    "LoginPasskeyError",
    "LoginResult",
    "NeedsHumanError",
    "NetworkError",
    "NotFoundError",
    "RefusedURLError",
    "RegistrationError",
    "Settings",
    "SignedIn",
    "VirtualAuthenticator",
    "authenticate",
    "fetch",
    "fetch_sync",
    "http_client",
    "merged_env",
    "save_cookies",
    "signed_in",
]
