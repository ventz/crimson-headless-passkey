"""Shared fixtures."""

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


@pytest.fixture(autouse=True)
def _isolate_user_config(tmp_path_factory, monkeypatch):
    """Never read or write the real ~/.config/crimson-headless-passkey/config.toml."""
    cfg = tmp_path_factory.mktemp("user-config") / "config.toml"
    monkeypatch.setenv("CRIMSON_HEADLESS_PASSKEY_CONFIG", str(cfg))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg.parent.parent / "xdg-config"))


class MemoryKeyring(KeyringBackend):
    """An in-process keychain, so no test ever touches the real one."""

    priority = 1

    def __init__(self):
        super().__init__()
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        if self.items.pop((service, username), None) is None:
            raise PasswordDeleteError("not found")


@pytest.fixture(autouse=True)
def memory_keyring():
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)
