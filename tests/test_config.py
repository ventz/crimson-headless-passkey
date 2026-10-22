from pathlib import Path

import pytest

from crimson_headless_passkey.config import (
    DEFAULT_IDP_HOSTS,
    Settings,
    default_data_dir,
    is_idp_url,
    is_signed_in_url,
    parse_hosts,
    redact_url,
    validate_url,
)


def test_data_dir_prefers_explicit_home():
    assert default_data_dir({"CRIMSON_HEADLESS_PASSKEY_HOME": "/x/y"}) == Path("/x/y")


def test_data_dir_uses_xdg_data_home():
    assert default_data_dir({"XDG_DATA_HOME": "/d"}) == Path("/d/crimson-headless-passkey")


def test_data_dir_default():
    assert default_data_dir({}) == Path.home() / ".local/share/crimson-headless-passkey"


def test_parse_hosts_normalizes():
    assert parse_hosts(" A.example.com, ,b.example.com ") == ("a.example.com", "b.example.com")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://login.harvard.edu/app?x=1", True),
        ("https://HARVARD.okta.com/signin", True),
        ("https://portal.harvard.edu/", False),
        # An IdP host in the query string or path must not count as being on the IdP.
        ("https://portal.harvard.edu/cb?redirect_uri=https://login.harvard.edu/", False),
        ("https://evil.example/login.harvard.edu", False),
        ("https://login.harvard.edu.evil.example/", False),
        ("about:blank", False),
    ],
)
def test_is_idp_url(url, expected):
    assert is_idp_url(url, DEFAULT_IDP_HOSTS) is expected


@pytest.mark.parametrize(
    "url",
    [
        "login.harvard.edu",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "http://login.harvard.edu",
    ],
)
def test_validate_url_rejects(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_settings_precedence():
    env = {
        "CRIMSON_HEADLESS_PASSKEY_URL": "https://env.example",
        "CRIMSON_HEADLESS_PASSKEY_RP_ID": "env.example",
        "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS": "a.example,b.example",
        "CRIMSON_HEADLESS_PASSKEY_HOME": "/env",
    }
    s = Settings.from_env(env=env)
    assert (s.login_url, s.rp_id, s.idp_hosts, s.data_dir) == (
        "https://env.example",
        "env.example",
        ("login.harvard.edu", "harvard.okta.com", "key.harvard.edu", "a.example", "b.example"),
        Path("/env"),
    )
    s = Settings.from_env(
        env=env, login_url="https://arg.example", rp_id="ARG.example", idp_hosts=["X.example"]
    )
    # Configured hosts ADD to the built-ins; they never replace them.
    assert (s.login_url, s.rp_id, s.idp_hosts) == (
        "https://arg.example",
        "arg.example",
        ("login.harvard.edu", "harvard.okta.com", "key.harvard.edu", "x.example"),
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://portal.harvard.edu/", True),
        ("https://login.harvard.edu/account-settings/home", True),
        ("https://harvard.okta.com/app/UserHome", True),
        ("https://login.harvard.edu/app/bookmark/0oa1/login", False),
        ("https://login.harvard.edu/", False),
        ("about:blank", False),
        # Chromium's error page parses as host "chromewebdata": never a success.
        ("chrome-error://chromewebdata/", False),
        ("http://portal.harvard.edu/", False),
        ("http://localhost:8000/", True),
        # Signed-in paths match whole segments only.
        ("https://login.harvard.edu/app/UserHomeX", False),
        ("https://login.harvard.edu/account-settings", True),
    ],
)
def test_is_signed_in_url(url, expected):
    assert is_signed_in_url(url, DEFAULT_IDP_HOSTS) is expected


def test_username_from_env_or_argument():
    assert Settings.from_env(env={}).username is None
    env = {"CRIMSON_HEADLESS_PASSKEY_USERNAME": "env-user"}
    assert Settings.from_env(env=env).username == "env-user"
    assert Settings.from_env(env=env, username="arg-user").username == "arg-user"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://app.example/cb?code=SECRET&state=x",
            "https://app.example/cb (query/fragment hidden)",
        ),
        (
            "https://app.example/#access_token=SECRET",
            "https://app.example/ (query/fragment hidden)",
        ),
        ("https://app.example/home", "https://app.example/home"),
    ],
)
def test_redact_url(url, expected):
    assert redact_url(url) == expected
    assert "SECRET" not in redact_url(url)


def test_data_dir_is_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert Settings.from_env(env={}, data_dir="rel").data_dir == tmp_path / "rel"
