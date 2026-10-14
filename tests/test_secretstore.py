"""Keeping the private key in the OS keychain (an in-memory one here, see conftest)."""

import json

import pytest
from keyring.errors import KeyringError, KeyringLocked

from crimson_headless_passkey import secretstore, storage
from crimson_headless_passkey.config import Settings
from crimson_headless_passkey.errors import CredentialFileError, KeychainError

CRED = {
    "credentialId": "Y3JlZA==",
    "rpId": "login.example.edu",
    "privateKey": "cHJpdmF0ZQ==",
    "signCount": 1,
    "userHandle": "dXNlcg==",
}
ACCOUNT = (secretstore.SERVICE, "login.example.edu/Y3JlZA==")


def test_keychain_store_keeps_the_key_out_of_the_file(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED], secretstore.KEYCHAIN)

    (entry,) = json.loads(target.read_text())
    assert "privateKey" not in entry
    assert "cHJpdmF0ZQ==" not in target.read_text()
    assert entry["keyStore"] == "keychain"
    assert memory_keyring.items[ACCOUNT] == "cHJpdmF0ZQ=="

    (loaded,) = storage.load_credentials(target)
    assert loaded["privateKey"] == "cHJpdmF0ZQ=="
    assert loaded["keyStore"] == "keychain"


def test_moving_a_file_key_into_the_keychain(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    creds = storage.load_credentials(target)
    assert creds[0]["keyStore"] == "file"

    storage.save_credentials(target, creds, secretstore.KEYCHAIN)
    assert "cHJpdmF0ZQ==" not in target.read_text()
    assert memory_keyring.items[ACCOUNT] == "cHJpdmF0ZQ=="
    assert creds[0]["keyStore"] == "keychain"


def test_moving_back_to_the_file_removes_the_keychain_item(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED], secretstore.KEYCHAIN)
    creds = storage.load_credentials(target)

    storage.save_credentials(target, creds, secretstore.FILE)
    assert json.loads(target.read_text())[0]["privateKey"] == "cHJpdmF0ZQ=="
    assert ACCOUNT not in memory_keyring.items


def test_sign_count_saves_keep_the_key_in_the_keychain(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED], secretstore.KEYCHAIN)
    creds = storage.load_credentials(target)
    storage.apply_sign_counts(creds, {"Y3JlZA==": 7})
    storage.save_credentials(target, creds, secretstore.KEYCHAIN)

    assert "privateKey" not in json.loads(target.read_text())[0]
    assert storage.load_credentials(target)[0]["signCount"] == 7


def test_missing_keychain_item_says_what_to_do(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED], secretstore.KEYCHAIN)
    memory_keyring.items.clear()
    with pytest.raises(CredentialFileError, match="not in the keychain"):
        storage.load_credentials(target)


def test_failed_keychain_write_leaves_the_file_holding_the_key(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    creds = storage.load_credentials(target)

    def refuse(*_):
        raise KeyringError("locked")

    memory_keyring.set_password = refuse
    with pytest.raises(KeychainError, match="could not store"):
        storage.save_credentials(target, creds, secretstore.KEYCHAIN)
    assert json.loads(target.read_text())[0]["privateKey"] == "cHJpdmF0ZQ=="


def test_unknown_secret_store_in_file_is_refused(tmp_path):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED])
    data = json.loads(target.read_text())
    data[0]["keyStore"] = "cloud"
    storage.write_private_json(target, data)
    with pytest.raises(CredentialFileError, match="unknown keyStore"):
        storage.load_credentials(target)


def test_forget_keys_removes_only_replaced_credentials(tmp_path, memory_keyring):
    other = {**CRED, "credentialId": "b3RoZXI="}
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED, other], secretstore.KEYCHAIN)
    old = storage.read_entries(target)

    storage.forget_keys(old, keep=[other])
    assert ACCOUNT not in memory_keyring.items
    assert (secretstore.SERVICE, "login.example.edu/b3RoZXI=") in memory_keyring.items


def test_secret_store_setting():
    assert Settings.from_env(env={}).secret_store == secretstore.default_secret_store()
    env = {"CRIMSON_HEADLESS_PASSKEY_SECRET_STORE": "File"}
    assert Settings.from_env(env=env).secret_store == "file"
    assert Settings.from_env(env=env, secret_store="keychain").secret_store == "keychain"
    with pytest.raises(ValueError, match="secret store"):
        Settings.from_env(env={"CRIMSON_HEADLESS_PASSKEY_SECRET_STORE": "cloud"})


def test_default_is_the_keychain_only_on_macos(monkeypatch):
    monkeypatch.setattr(secretstore.sys, "platform", "darwin")
    assert secretstore.default_secret_store() == "keychain"
    monkeypatch.setattr(secretstore.sys, "platform", "linux")
    assert secretstore.default_secret_store() == "file"


def test_locked_keychain_explains_the_logged_out_case(tmp_path, memory_keyring):
    target = tmp_path / "creds.json"
    storage.save_credentials(target, [CRED], secretstore.KEYCHAIN)

    def locked(*_):
        raise KeyringLocked("interaction not allowed")

    memory_keyring.get_password = locked
    with pytest.raises(KeychainError, match="logged in"):
        storage.load_credentials(target)


STATE = {"cookies": [{"name": "sid", "value": "s3cret", "domain": "idp.example"}], "origins": []}


def session_item(memory_keyring, data_dir):
    raw = memory_keyring.items.get((secretstore.SERVICE, f"session:{data_dir}"))
    return json.loads(raw) if raw else None


def test_keychain_session_leaves_no_file(tmp_path, memory_keyring):
    target = tmp_path / "auth_state.json"
    storage.save_auth_state(target, STATE, secretstore.KEYCHAIN)
    assert not target.exists()
    assert session_item(memory_keyring, tmp_path)["state"] == STATE
    assert storage.load_auth_state(target, secretstore.KEYCHAIN) == STATE


def test_session_moves_into_the_keychain_and_the_file_goes(tmp_path, memory_keyring):
    target = tmp_path / "auth_state.json"
    storage.save_auth_state(target, STATE)
    assert storage.move_auth_state(target, secretstore.KEYCHAIN)
    assert not target.exists()
    assert session_item(memory_keyring, tmp_path)["state"] == STATE
    assert not storage.move_auth_state(target, secretstore.KEYCHAIN)  # nothing left to move


def test_session_moves_back_to_a_file(tmp_path, memory_keyring):
    target = tmp_path / "auth_state.json"
    storage.save_auth_state(target, STATE, secretstore.KEYCHAIN)
    assert storage.load_auth_state(target, secretstore.FILE) == STATE  # found before the move
    assert storage.move_auth_state(target, secretstore.FILE)
    assert json.loads(target.read_text()) == STATE
    assert session_item(memory_keyring, tmp_path) is None


def test_failed_keychain_session_write_keeps_the_file(tmp_path, memory_keyring):
    target = tmp_path / "auth_state.json"
    storage.save_auth_state(target, STATE)

    def refuse(*_):
        raise KeyringError("locked")

    memory_keyring.set_password = refuse
    with pytest.raises(KeychainError, match="could not store the browser session"):
        storage.move_auth_state(target, secretstore.KEYCHAIN)
    assert json.loads(target.read_text()) == STATE


def test_file_store_works_without_any_keychain(tmp_path, memory_keyring):
    """Headless Linux: no Secret Service at all must not break the file store."""
    from keyring.errors import NoKeyringError

    def missing(*_):
        raise NoKeyringError("no backend")

    memory_keyring.get_password = missing
    memory_keyring.set_password = missing
    memory_keyring.delete_password = missing
    target = tmp_path / "auth_state.json"
    storage.save_auth_state(target, STATE, secretstore.FILE)
    assert storage.load_auth_state(target, secretstore.FILE) == STATE
    assert not storage.move_auth_state(target, secretstore.FILE)
    assert storage.load_auth_state(tmp_path / "none.json", secretstore.FILE) is None
