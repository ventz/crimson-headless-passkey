"""Where the secrets live: the OS keychain or files in the data directory.

There are two secrets: the passkey's private key and the saved browser session
(cookies). With the keychain store (the default on macOS) both go into the
login keychain through ``keyring``, and the data directory keeps only
non-secret fields and the sign counter. They are then encrypted at rest and
tied to your login, instead of sitting in files that a backup, a sync folder
or a stray copy could leak.

The file store keeps both in ``0600`` files. It exists for machines where
nobody is logged in to unlock a keychain (servers, CI): fully hands-off, at
the cost of secrets on disk.

Either way the key is handed to Chrome in memory at sign-in, so the keychain
protects secrets at rest, not from code already running as you.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any

from .errors import KeychainError

KEYCHAIN = "keychain"
FILE = "file"
SECRET_STORES = (KEYCHAIN, FILE)

# Keychain items share this "service" name. Accounts are "<rpId>/<credentialId>"
# for private keys and "session:<data dir>" for the saved session.
SERVICE = "crimson-headless-passkey"


def default_secret_store() -> str:
    """The keychain on macOS, where it is always available; files elsewhere.

    Linux servers rarely have an unlocked Secret Service, so the keychain is
    opt-in there (``--secret-store keychain``).
    """
    return KEYCHAIN if sys.platform == "darwin" else FILE


def parse_secret_store(value: str) -> str:
    store = value.strip().lower()
    if store not in SECRET_STORES:
        raise ValueError(f"secret store must be one of {', '.join(SECRET_STORES)}, not {value!r}")
    return store


def account(cred: Mapping[str, Any]) -> str:
    """The keychain account for a credential's private key."""
    return f"{cred['rpId']}/{cred['credentialId']}"


def session_account(data_dir: object) -> str:
    """The keychain account for the session saved by one data directory."""
    return f"session:{data_dir}"


LOCKED_HINT = (
    "The keychain is locked. The login keychain opens when you log in to this computer "
    "and locks when you log out, so a scheduled run needs you logged in (a locked screen "
    "is fine). On a machine where nobody is logged in, use --secret-store file."
)


def _keyring() -> Any:
    try:
        import keyring
        from keyring.errors import KeyringError
    except ImportError as e:  # pragma: no cover - keyring is a dependency
        raise KeychainError("the keychain store needs the keyring package") from e
    return keyring, KeyringError


def _failure(action: str, e: Exception) -> KeychainError:
    from keyring.errors import KeyringLocked, NoKeyringError

    if isinstance(e, KeyringLocked):
        return KeychainError(f"could not {action}: {LOCKED_HINT}")
    if isinstance(e, NoKeyringError):
        return KeychainError(
            f"could not {action}: no keychain is available on this system. Use --secret-store file."
        )
    return KeychainError(f"could not {action}: {e}")


def get_secret(name: str, what: str) -> str | None:
    keyring, keyring_error = _keyring()
    try:
        return keyring.get_password(SERVICE, name)
    except keyring_error as e:
        raise _failure(f"read the {what} from the keychain", e) from e


def put_secret(name: str, value: str, what: str) -> None:
    """Store a secret, skipping the write when the keychain already has it."""
    if get_secret(name, what) == value:
        return
    keyring, keyring_error = _keyring()
    try:
        keyring.set_password(SERVICE, name, value)
    except keyring_error as e:
        raise _failure(f"store the {what} in the keychain", e) from e


def delete_secret(name: str, what: str) -> None:
    """Remove a secret; a missing item is fine."""
    keyring, keyring_error = _keyring()
    from keyring.errors import PasswordDeleteError

    try:
        keyring.delete_password(SERVICE, name)
    except PasswordDeleteError:
        pass
    except keyring_error as e:
        raise _failure(f"remove the {what} from the keychain", e) from e


def get_key(cred: Mapping[str, Any]) -> str | None:
    return get_secret(account(cred), "private key")


def put_key(cred: Mapping[str, Any]) -> None:
    put_secret(account(cred), cred["privateKey"], "private key")


def delete_key(cred: Mapping[str, Any]) -> None:
    delete_secret(account(cred), "private key")
