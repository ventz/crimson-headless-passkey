"""Owner-only, atomic storage for the passkey credential and browser state.

Two things are secret: the passkey's private key and the saved session's
cookies. With the keychain store both live in the OS keychain (see
``secretstore``) and the credential file holds only non-secret fields and the
sign counter. With the file store both are files here. They are written 0600 through a temp
file and ``os.replace``. Loading applies SSH's rules: the file must be a
regular file we own that nobody else can read, and its directory must be ours
and not writable by anybody else.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import datetime as dt
import json
import os
import stat
import sys
import tempfile
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from . import secretstore
from .errors import CredentialFileError, InsecurePermissionsError, KeychainError

# Fields CDP needs to re-inject a credential, and the base64 ones among them.
REQUIRED_FIELDS = ("credentialId", "rpId", "privateKey", "signCount", "userHandle")
BASE64_FIELDS = ("credentialId", "privateKey", "userHandle")
OPTIONAL_FIELDS = ("userName", "userDisplayName", "backupEligibility", "backupState")

LOCK_FILENAME = ".lock"

POSIX = os.name == "posix"


def ensure_private_dir(path: Path) -> None:
    """Create the data directory owner-only (0700), then check it."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private_dir(path)


def check_private_dir(path: Path) -> None:
    """Raise unless the directory is ours and nobody else can write to it."""
    if not POSIX:
        return
    st = path.stat()  # follows a symlinked data dir; its target is what matters
    if not stat.S_ISDIR(st.st_mode):
        raise CredentialFileError(f"{path} is not a directory")
    if st.st_uid != os.getuid():
        raise InsecurePermissionsError(f"{path} is not owned by the current user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise InsecurePermissionsError(
            f"{path} is writable by other users (mode {stat.filemode(st.st_mode)}). "
            f"Fix with: chmod 700 {path}"
        )


def check_private_stat(path: Path, st: os.stat_result) -> None:
    """Raise unless ``st`` describes a regular file we own with no group/other access."""
    if not stat.S_ISREG(st.st_mode):
        raise CredentialFileError(f"{path} is not a regular file")
    if not POSIX:
        return
    if st.st_uid != os.getuid():
        raise InsecurePermissionsError(f"{path} is not owned by the current user")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise InsecurePermissionsError(
            f"{path} is accessible by other users (mode {stat.filemode(st.st_mode)}). "
            f"Fix with: chmod 600 {path}"
        )


def check_private(path: Path) -> None:
    check_private_stat(path, path.stat())


def read_private_json(path: Path) -> Any:
    """Open without following symlinks, check the open file itself, then parse it.

    Checking the descriptor rather than the path closes the window between a
    permission check and the read.
    """
    check_private_dir(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise CredentialFileError(f"cannot open {path}: {e.strerror}") from e
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        check_private_stat(path, os.fstat(f.fileno()))
        try:
            return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise CredentialFileError(f"{path} is not valid JSON: {e}") from e


def write_private_json(path: Path, data: Any) -> None:
    """Atomically write JSON with mode 0600 (mkstemp creates files 0600)."""
    ensure_private_dir(path.parent)
    remove_stale_temp_files(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    fsync_dir(path.parent)


def fsync_dir(path: Path) -> None:
    """Make the rename durable, so a crash cannot roll the signCount back."""
    if not POSIX:
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_stale_temp_files(path: Path) -> None:
    """Delete temp files a killed write left behind (they may hold the private key)."""
    for leftover in path.parent.glob(f".{path.name}.*.tmp"):
        with contextlib.suppress(OSError):
            leftover.unlink()


def is_base64(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def credential_from_cdp(cred: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a CDP WebAuthn credential and keep only the fields worth saving."""
    missing = [k for k in REQUIRED_FIELDS if k not in cred]
    if missing:
        raise CredentialFileError(f"credential is missing {', '.join(missing)}")
    bad = [k for k in BASE64_FIELDS if not is_base64(cred[k])]
    if bad:
        raise CredentialFileError(f"credential fields are not valid base64: {', '.join(bad)}")
    count = cred["signCount"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise CredentialFileError("credential signCount must be a non-negative integer")
    if not isinstance(cred["rpId"], str) or not cred["rpId"]:
        raise CredentialFileError("credential rpId must be a non-empty string")
    saved = {k: cred[k] for k in REQUIRED_FIELDS}
    saved["isResidentCredential"] = cred.get("isResidentCredential", True)
    saved.update({k: cred[k] for k in OPTIONAL_FIELDS if k in cred})
    return saved


def read_entries(path: Path) -> list[dict[str, Any]]:
    """The credential file's entries as stored, without fetching keys from the keychain."""
    if not path.exists():
        raise CredentialFileError(
            f"{path} not found. Run `crimson-headless-passkey register` first "
            "(or point --data-dir / CRIMSON_HEADLESS_PASSKEY_HOME at an existing one)."
        )
    data = read_private_json(path)
    if not isinstance(data, list) or not data or not all(isinstance(c, dict) for c in data):
        raise CredentialFileError(f"{path} must be a non-empty JSON list of credentials")
    return data


def load_credentials(path: Path) -> list[dict[str, Any]]:
    """Validated credentials with their private keys, wherever each key is kept.

    Each one carries ``keyStore`` (``file`` or ``keychain``) saying where its
    key came from, so a later save can move it.
    """
    credentials = []
    for entry in read_entries(path):
        where = entry.get("keyStore", secretstore.FILE)
        if where not in secretstore.SECRET_STORES:
            raise CredentialFileError(f"{path}: unknown keyStore {where!r}")
        if where == secretstore.KEYCHAIN:
            if "rpId" not in entry or "credentialId" not in entry:
                raise CredentialFileError(f"{path}: a keychain entry needs rpId and credentialId")
            key = secretstore.get_key(entry)
            if key is None:
                raise CredentialFileError(
                    f"the private key for {secretstore.account(entry)[:40]}... is not in the "
                    f"keychain (service {secretstore.SERVICE!r}). Restore it, or run "
                    "`crimson-headless-passkey register --force` to enroll a new passkey."
                )
            entry = {**entry, "privateKey": key}
        cred = credential_from_cdp(entry)
        cred["keyStore"] = where
        credentials.append(cred)
    return credentials


def save_credentials(
    path: Path, credentials: list[Mapping[str, Any]], secret_store: str = secretstore.FILE
) -> None:
    """Write the credentials, with each private key kept in ``secret_store``.

    The order makes a crash safe: moving to the keychain stores the key there
    before the file stops holding it, and moving back to the file rewrites the
    file before the keychain item is removed. Moved credentials have their
    ``keyStore`` updated in place.
    """
    validated = [credential_from_cdp(c) for c in credentials]
    if secret_store == secretstore.KEYCHAIN:
        for cred in validated:
            secretstore.put_key(cred)
        write_private_json(
            path,
            [
                {
                    **{k: v for k, v in c.items() if k != "privateKey"},
                    "keyStore": secretstore.KEYCHAIN,
                }
                for c in validated
            ],
        )
    else:
        write_private_json(path, validated)
        for cred in credentials:
            if cred.get("keyStore") == secretstore.KEYCHAIN:
                secretstore.delete_key(cred)
    for cred in credentials:
        if isinstance(cred, dict):
            cred["keyStore"] = secret_store


def forget_keys(entries: list[Mapping[str, Any]], keep: list[Mapping[str, Any]]) -> None:
    """Remove keychain items for credentials that were replaced (``register --force``)."""
    kept = {secretstore.account(c) for c in keep}
    for entry in entries:
        if (
            entry.get("keyStore") == secretstore.KEYCHAIN
            and "rpId" in entry
            and "credentialId" in entry
            and secretstore.account(entry) not in kept
        ):
            secretstore.delete_key(entry)


def apply_sign_counts(credentials: list[dict[str, Any]], counts: Mapping[str, int]) -> bool:
    """Raise stored signCounts to the authenticator's values. Returns True if any changed.

    Counts only move forward: a lower observed value never overwrites a higher
    stored one, since relying parties treat a counter going backwards as a
    sign of a cloned authenticator.
    """
    changed = False
    for cred in credentials:
        observed = counts.get(cred["credentialId"])
        if isinstance(observed, int) and observed > cred["signCount"]:
            cred["signCount"] = observed
            changed = True
    return changed


SESSION = "browser session"


def _session_from_file(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    state = read_private_json(path)
    if not isinstance(state, dict):
        raise CredentialFileError(f"{path} is not a Playwright storage state object")
    return state


def _keychain_session(path: Path, *, quiet: bool = False) -> dict[str, Any] | None:
    """The session saved in the keychain for this data directory, if any.

    ``quiet`` turns "no keychain here" into None, for the file store, which
    only looks in the keychain to move a session out of it.
    """
    try:
        raw = secretstore.get_secret(secretstore.session_account(path.parent), SESSION)
    except KeychainError:
        if quiet:
            return None
        raise
    if raw is None:
        return None
    try:
        saved = json.loads(raw)
        state = saved["state"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise CredentialFileError("the session saved in the keychain is not valid") from e
    if not isinstance(state, dict):
        raise CredentialFileError("the session saved in the keychain is not valid")
    return state


def load_auth_state(path: Path, secret_store: str = secretstore.FILE) -> dict[str, Any] | None:
    """Playwright storage state, or None when there is none saved yet.

    Looks in the configured store first, then in the other place, so a
    session saved before a store change is still used until it is moved.
    """
    if secret_store == secretstore.KEYCHAIN:
        return _keychain_session(path) or _session_from_file(path)
    return _session_from_file(path) or _keychain_session(path, quiet=True)


def save_auth_state(
    path: Path, state: Mapping[str, Any], secret_store: str = secretstore.FILE
) -> None:
    """Save the session in ``secret_store`` and remove any copy in the other place.

    The new copy is written before the old one is removed.
    """
    name = secretstore.session_account(path.parent)
    if secret_store == secretstore.KEYCHAIN:
        saved_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
        secretstore.put_secret(
            name, json.dumps({"savedAt": saved_at, "state": dict(state)}), SESSION
        )
        remove_private_file(path)
    else:
        write_private_json(path, dict(state))
        with contextlib.suppress(KeychainError):  # no keychain here: nothing to remove
            secretstore.delete_secret(name, SESSION)


def move_auth_state(path: Path, secret_store: str) -> bool:
    """Move a saved session into ``secret_store``. Returns True if one moved."""
    if secret_store == secretstore.KEYCHAIN:
        state = _session_from_file(path)
    else:
        state = None if path.exists() else _keychain_session(path, quiet=True)
    if state is None:
        return False
    save_auth_state(path, state, secret_store)
    return True


def session_summary(path: Path) -> tuple[str, dict[str, Any], str] | None:
    """Where the session is, the state itself and when it was saved, for ``status``."""
    if path.exists():
        state = _session_from_file(path) or {}
        mtime = dt.datetime.fromtimestamp(path.stat().st_mtime)
        return str(path), state, f"{mtime:%Y-%m-%d %H:%M}"
    raw = None
    with contextlib.suppress(KeychainError):
        raw = secretstore.get_secret(secretstore.session_account(path.parent), SESSION)
    if raw is None:
        return None
    state = _keychain_session(path) or {}
    try:
        saved_at = dt.datetime.fromisoformat(json.loads(raw)["savedAt"]).astimezone()
        saved = f"{saved_at:%Y-%m-%d %H:%M}"
    except (KeyError, ValueError, TypeError):
        saved = "unknown time"
    return "keychain", state, saved


def remove_private_file(path: Path) -> None:
    """Delete a secret file (and temp files a killed write left), durably."""
    remove_stale_temp_files(path)
    if path.exists():
        path.unlink()
        fsync_dir(path.parent)


@contextlib.contextmanager
def locked(data_dir: Path) -> Iterator[None]:
    """Hold an exclusive lock on the data dir for one sign-in.

    Two runs at once would both load signCount N and both present N+1, so the
    second presents a counter that did not move forward. The lock serializes
    them. POSIX only; elsewhere this is a no-op.
    """
    if not POSIX:
        yield
        return
    import fcntl

    ensure_private_dir(data_dir)
    fd = os.open(data_dir / LOCK_FILENAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another run is using this credential; waiting for it...", file=sys.stderr)
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock
