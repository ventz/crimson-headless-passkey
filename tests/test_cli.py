"""CLI behavior that does not need a browser: arguments, exit codes, messages."""

import pytest

from crimson_headless_passkey import storage
from crimson_headless_passkey.cli import EXIT_ERROR, EXIT_OK, main


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch, tmp_path):
    for name in (
        "CRIMSON_HEADLESS_PASSKEY_HOME",
        "CRIMSON_HEADLESS_PASSKEY_URL",
        "CRIMSON_HEADLESS_PASSKEY_RP_ID",
        "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS",
        "CRIMSON_HEADLESS_PASSKEY_USERNAME",
        "CRIMSON_HEADLESS_PASSKEY_SECRET_STORE",
        "DEBUG",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    # A developer's own .env in the repo must not leak into these tests.
    monkeypatch.chdir(tmp_path)


def test_status_with_nothing_stored(tmp_path, capsys):
    assert main(["status", "--data-dir", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "credential:   none" in out
    assert "session:      none" in out


def test_status_never_prints_the_private_key(tmp_path, capsys):
    cred = {
        "credentialId": "Y3JlZGVudGlhbA==",
        "rpId": "login.harvard.edu",
        "privateKey": "U0VDUkVUS0VZ",
        "signCount": 4,
        "userHandle": "dXNlcg==",
    }
    storage.save_credentials(tmp_path / "passkey_credential.json", [cred])
    assert main(["status", "--data-dir", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "signCount 4" in out
    assert "U0VDUkVUS0VZ" not in out


def test_status_says_where_the_key_is(tmp_path, capsys):
    cred = {
        "credentialId": "Y3JlZGVudGlhbA==",
        "rpId": "login.harvard.edu",
        "privateKey": "U0VDUkVUS0VZ",
        "signCount": 4,
        "userHandle": "dXNlcg==",
    }
    storage.save_credentials(tmp_path / "passkey_credential.json", [cred])
    args = ["status", "--data-dir", str(tmp_path), "--secret-store", "keychain"]
    assert main(args) == EXIT_OK
    out = capsys.readouterr().out
    assert "secret store: keychain" in out
    assert "key in credential file (moves to the keychain on the next sign-in)" in out
    assert "U0VDUkVUS0VZ" not in out


def test_login_without_credential_exits_2_before_starting_a_browser(tmp_path, capsys):
    assert main(["login", "--data-dir", str(tmp_path), "--headless"]) == EXIT_ERROR
    assert "register" in capsys.readouterr().err


def test_keep_open_with_headless_is_rejected(tmp_path, capsys):
    rc = main(["login", "--data-dir", str(tmp_path), "--headless", "--keep-open"])
    assert rc == EXIT_ERROR
    assert "--headless" in capsys.readouterr().err


def test_unsafe_permissions_exit_2(tmp_path, capsys):
    target = tmp_path / "passkey_credential.json"
    target.write_text("[]")
    target.chmod(0o644)
    assert main(["status", "--data-dir", str(tmp_path)]) == EXIT_ERROR
    assert "chmod 600" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["login", "--timeout", "0"],
        ["login", "--timeout", "soon"],
        ["login", "http://insecure.example/"],
        ["login", "--idp-host", ""],
        ["login", "--idp-host", "https://okta.example/"],
        ["open", "javascript:alert(1)"],
    ],
)
def test_bad_arguments_exit_2(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_protocol_logging_warning(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DEBUG", "pw:protocol")
    main(["status", "--data-dir", str(tmp_path)])
    assert "private key" in capsys.readouterr().err


def test_settings_come_from_dot_env(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text(
        "CRIMSON_HEADLESS_PASSKEY_URL=https://example.okta.com\n"
        "CRIMSON_HEADLESS_PASSKEY_RP_ID=example.okta.com\n"
        "CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS=example.okta.com\n"
        "CRIMSON_HEADLESS_PASSKEY_USERNAME=someone\n"
    )
    env.chmod(0o600)
    assert main(["status", "--data-dir", str(tmp_path / "data")]) == EXIT_OK
    out = capsys.readouterr().out
    assert "login URL:    https://example.okta.com" in out
    assert "IdP hosts:    example.okta.com" in out
    assert "username:     someone" in out


def test_flags_beat_dot_env(tmp_path, capsys):
    env = tmp_path / "custom.env"
    env.write_text("CRIMSON_HEADLESS_PASSKEY_RP_ID=file.example\n")
    env.chmod(0o600)
    argv = ["status", "--env-file", str(env), "--rp-id", "flag.example"]
    assert main([*argv, "--data-dir", str(tmp_path / "d")]) == EXIT_OK
    assert "rpId:         flag.example" in capsys.readouterr().out


def test_bad_dot_env_exits_2(tmp_path, capsys):
    (tmp_path / ".env").write_text("not a setting\n")
    (tmp_path / ".env").chmod(0o600)
    assert main(["status"]) == EXIT_ERROR
    assert ".env:1" in capsys.readouterr().err


def test_status_shows_a_session_in_the_keychain(tmp_path, capsys):
    state = {"cookies": [{"name": "sid", "value": "c2Vzc2lvbg"}], "origins": []}
    storage.save_auth_state(tmp_path / "auth_state.json", state, "keychain")
    assert main(["status", "--data-dir", str(tmp_path), "--secret-store", "keychain"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "session:      in the keychain (1 cookies" in out
    assert "c2Vzc2lvbg" not in out


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["open", "--no-auth", "https://idp.example/account/"], "plain"),
        (["open", "https://idp.example/account/"], "signed-in"),
    ],
)
def test_open_is_signed_in_unless_no_auth(tmp_path, monkeypatch, argv, expected):
    """`open URL` and `open --no-auth URL` are the same page, with and without the passkey."""
    from crimson_headless_passkey import flows

    calls = []

    async def fake_open_url(url, *, channel=None, verbose=False):
        calls.append(("plain", url))

    async def fake_login(settings, url, **kwargs):
        calls.append(("signed-in", url, kwargs["keep_open"], kwargs["headless"]))
        return True

    monkeypatch.setattr(flows, "open_url", fake_open_url)
    monkeypatch.setattr(flows, "login", fake_login)
    assert main([*argv, "--data-dir", str(tmp_path)]) == EXIT_OK
    assert calls[0][0] == expected
    assert calls[0][1] == "https://idp.example/account/"
    if expected == "signed-in":
        assert calls[0][2:] == (True, False)  # headed and left open


def test_verbose_flag_reaches_login_and_open(tmp_path, monkeypatch):
    from crimson_headless_passkey import flows

    seen = []

    async def fake_login(settings, url, **kwargs):
        seen.append(("login", kwargs["verbose"]))
        return True

    async def fake_open_url(url, *, channel=None, verbose=False):
        seen.append(("open", verbose))

    monkeypatch.setattr(flows, "login", fake_login)
    monkeypatch.setattr(flows, "open_url", fake_open_url)
    data = ["--data-dir", str(tmp_path)]
    assert main(["login", "-v", "--headless", "--close", *data]) == EXIT_OK
    assert main(["open", "--verbose", *data]) == EXIT_OK
    assert main(["open", "--no-auth", "-v", *data]) == EXIT_OK
    assert main(["login", "--headless", "--close", *data]) == EXIT_OK
    assert seen == [("login", True), ("login", True), ("open", True), ("login", False)]


def test_navigation_log_hides_queries_and_repeats():
    import io

    from crimson_headless_passkey.flows import NavigationLog

    out = io.StringIO()
    log = NavigationLog(out)
    log("https://idp.example/authorize?code=SECRET&state=x")
    log("https://idp.example/authorize?code=OTHER")  # same page again: shown once
    log("https://app.example/home#token=SECRET")
    text = out.getvalue()
    assert "SECRET" not in text and "OTHER" not in text
    assert text.count("idp.example/authorize") == 1
    assert "app.example/home" in text


ESC = "\x1b"


@pytest.mark.parametrize(
    "raw",
    [
        f"{ESC}[1;32mhttps://idp.example/account/{ESC}[0m",
        "  https://idp.example/account/\n",
        f"{ESC}]8;;https://idp.example/account/{ESC}\\https://idp.example/account/{ESC}]8;;{ESC}\\",
        f"\thttps://idp.example/acc\nount/ {ESC}[K",
    ],
)
def test_url_argument_is_cleaned_of_colors_and_whitespace(tmp_path, monkeypatch, raw):
    from crimson_headless_passkey import flows

    seen = []

    async def fake_login(settings, url, **kwargs):
        seen.append(url)
        return True

    monkeypatch.setattr(flows, "login", fake_login)
    assert main(["login", "--headless", "--close", "--data-dir", str(tmp_path), raw]) == EXIT_OK
    assert seen == ["https://idp.example/account/"]


def test_colored_insecure_url_is_still_rejected():
    with pytest.raises(SystemExit) as exc:
        main(["login", f"{ESC}[31mhttp://insecure.example/{ESC}[0m"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("url", "bad"),
    [
        ("chrome-error://chromewebdata/", True),
        ("about:blank", True),
        ("data:text/html,hi", True),
        ("file:///etc/passwd", True),
        ("https://app.example/home", False),
        ("http://127.0.0.1:8080/oauth/callback", False),
    ],
)
def test_final_url_problem(url, bad):
    from crimson_headless_passkey.config import final_url_problem

    assert (final_url_problem(url) is not None) == bad


def test_aws_allow_flag_reaches_login(tmp_path, monkeypatch):
    from crimson_headless_passkey import flows

    seen = []

    async def fake_login(settings, url, **kwargs):
        seen.append(kwargs["aws_allow"])
        return True

    monkeypatch.setattr(flows, "login", fake_login)
    data = ["--data-dir", str(tmp_path)]
    assert main(["login", "--headless", "--close", "--aws-allow", *data]) == EXIT_OK
    assert main(["login", "--headless", "--close", *data]) == EXIT_OK
    assert main(["open", "--aws-allow", *data]) == EXIT_OK
    assert seen == [True, False, True]


def test_login_never_saves_a_session_that_ended_on_an_error_page(tmp_path, monkeypatch, capsys):
    """Even if authenticate() said ok, login() rechecks the final URL before saving."""
    import asyncio
    import contextlib

    from crimson_headless_passkey import flows

    saved = []

    class Page:
        url = "chrome-error://chromewebdata/"

    class Context:
        async def storage_state(self):
            return {"cookies": [], "origins": []}

    class Browser:
        async def close(self):
            pass

    @contextlib.asynccontextmanager
    async def fake_playwright():
        yield object()

    async def fake_launch(p, **kwargs):
        return Browser()

    async def fake_authenticate(browser, settings, url, **kwargs):
        return flows.LoginResult(ok=True, context=Context(), page=Page())

    monkeypatch.setattr(flows.storage, "load_credentials", lambda path: [])
    monkeypatch.setattr(flows, "select_credentials", lambda creds, settings: creds)
    monkeypatch.setattr(flows, "async_playwright", fake_playwright)
    monkeypatch.setattr(flows, "launch", fake_launch)
    monkeypatch.setattr(flows, "authenticate", fake_authenticate)
    monkeypatch.setattr(flows.storage, "save_auth_state", lambda *a: saved.append(a))

    settings = flows.Settings.from_env(data_dir=tmp_path, env={})
    ok = asyncio.run(flows.login(settings, "https://idp.example/", headless=True))
    out = capsys.readouterr().out
    assert ok is False
    assert saved == []
    assert "Signed in" not in out
    assert "error page" in out
