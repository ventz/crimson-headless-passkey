import json
import os
import stat

import pytest

from crimson_headless_passkey import storage
from crimson_headless_passkey.errors import CredentialFileError, InsecurePermissionsError

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")

CRED = {
    "credentialId": "Y3JlZA==",
    "rpId": "login.example.edu",
    "privateKey": "cHJpdmF0ZQ==",
    "signCount": 1,
    "isResidentCredential": False,
    "userHandle": "dXNlcg==",
    "userName": "someone",
    "backupState": False,
    "largeBlob": "",  # a CDP field we don't need: dropped on save
}


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@posix_only
def test_write_is_owner_only_and_creates_private_dir(tmp_path):
    target = tmp_path / "new" / "creds.json"
    storage.save_credentials(target, [CRED])
    assert mode(target) == 0o600
    assert mode(target.parent) == 0o700
    assert not list(target.parent.glob(".*.tmp")), "temp file left behind"


def test_roundtrip_keeps_only_known_fields(tmp_path):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    (loaded,) = storage.load_credentials(target)
    assert "largeBlob" not in loaded
    assert loaded["backupState"] is False
    assert loaded["userName"] == "someone"
    assert loaded["isResidentCredential"] is False


@posix_only
def test_overwrite_keeps_mode(tmp_path):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    storage.save_credentials(target, [{**CRED, "signCount": 9}])
    assert mode(target) == 0o600
    assert storage.load_credentials(target)[0]["signCount"] == 9


@posix_only
def test_load_refuses_group_or_world_readable(tmp_path):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    target.chmod(0o644)
    with pytest.raises(InsecurePermissionsError, match="chmod 600"):
        storage.load_credentials(target)


@posix_only
def test_load_auth_state_refuses_world_readable(tmp_path):
    target = tmp_path / "state.json"
    storage.save_auth_state(target, {"cookies": [], "origins": []})
    target.chmod(0o604)
    with pytest.raises(InsecurePermissionsError):
        storage.load_auth_state(target)


def test_missing_credential_file_explains_next_step(tmp_path):
    with pytest.raises(CredentialFileError, match="register"):
        storage.load_credentials(tmp_path / "nope.json")


@pytest.mark.parametrize("content", ["{}", "[]", "[1]", "not json", '[{"rpId": "x"}]', "\xff"])
def test_malformed_credential_file(tmp_path, content):
    target = tmp_path / "creds.json"
    target.write_text(content)
    target.chmod(0o600)
    with pytest.raises(CredentialFileError):
        storage.load_credentials(target)


def test_missing_auth_state_is_none(tmp_path):
    assert storage.load_auth_state(tmp_path / "none.json") is None


def test_failed_write_leaves_original_intact(tmp_path, monkeypatch):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(storage.os, "replace", boom)
    with pytest.raises(OSError):
        storage.save_credentials(target, [{**CRED, "signCount": 5}])
    assert json.loads(target.read_text())[0]["signCount"] == 1
    assert not list(tmp_path.glob(".*.tmp"))


def test_apply_sign_counts_only_moves_forward():
    creds = [dict(CRED, signCount=5), dict(CRED, credentialId="b3RoZXI=", signCount=2)]
    assert storage.apply_sign_counts(creds, {"Y3JlZA==": 7, "b3RoZXI=": 1, "unknown": 99})
    assert [c["signCount"] for c in creds] == [7, 2]
    assert not storage.apply_sign_counts(creds, {"Y3JlZA==": 7})


@pytest.mark.parametrize(
    "change",
    [
        {"userHandle": None},
        {"privateKey": "not base64!"},
        {"credentialId": "Y3JlZA"},  # missing padding: CDP rejects it
        {"signCount": -1},
        {"signCount": "5"},
        {"signCount": True},
        {"rpId": ""},
    ],
)
def test_invalid_credential_fields(tmp_path, change):
    cred = {**CRED, **change}
    if change.get("userHandle", "") is None:
        del cred["userHandle"]
    with pytest.raises(CredentialFileError):
        storage.save_credentials(tmp_path / "creds.json", [cred])


@posix_only
def test_refuses_symlinked_credential_file(tmp_path):
    real = tmp_path / "real.json"
    storage.save_credentials(real, [CRED])
    link = tmp_path / "creds.json"
    link.symlink_to(real)
    with pytest.raises(CredentialFileError, match="cannot open"):
        storage.load_credentials(link)


@posix_only
def test_refuses_non_regular_file(tmp_path):
    fifo = tmp_path / "creds.json"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(CredentialFileError, match="regular file"):
        storage.load_credentials(fifo)


@posix_only
def test_refuses_directory_writable_by_others(tmp_path):
    data = tmp_path / "data"
    storage.save_credentials(data / "creds.json", [CRED])
    data.chmod(0o777)
    try:
        with pytest.raises(InsecurePermissionsError, match="chmod 700"):
            storage.load_credentials(data / "creds.json")
        with pytest.raises(InsecurePermissionsError):
            storage.save_credentials(data / "creds.json", [CRED])
    finally:
        data.chmod(0o700)


def test_stale_temp_files_are_removed_on_write(tmp_path):
    target = tmp_path / "creds.json"
    leftover = tmp_path / ".creds.json.abc123.tmp"
    leftover.write_text("old private key")
    storage.save_credentials(target, [CRED])
    assert not leftover.exists()


@posix_only
def test_lock_is_exclusive(tmp_path):
    import fcntl

    with storage.locked(tmp_path):
        fd = os.open(tmp_path / storage.LOCK_FILENAME, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    fd = os.open(tmp_path / storage.LOCK_FILENAME, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released after the block
    finally:
        os.close(fd)
