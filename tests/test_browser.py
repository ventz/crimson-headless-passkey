"""End to end against a fake app and a fake IdP, entirely offline.

Requests to the fake origins are answered by Playwright routes, so nothing
leaves the machine. The flow mirrors the real one: the app bounces to the IdP,
the IdP may ask for a username, calls ``navigator.credentials.get()`` (answered
by the virtual authenticator) and redirects back. This covers the cross-origin
hops and the CDP events the real flow relies on.
"""

import asyncio

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from crimson_headless_passkey import storage
from crimson_headless_passkey.authenticator import VirtualAuthenticator
from crimson_headless_passkey.config import Settings
from crimson_headless_passkey.errors import CredentialFileError
from crimson_headless_passkey.flows import authenticate

pytestmark = pytest.mark.browser

APP = "https://app.example"
IDP = "https://idp.example"
DOWN = "https://down.example"

HELPERS = """
const b = s => Uint8Array.from(s, c => c.charCodeAt(0));
const challenge = b("0123456789abcdef");
// A short timeout, so a get() with no authenticator fails fast instead of hanging.
const assertion = () => navigator.credentials.get({publicKey: {
    challenge, rpId: "idp.example", userVerification: "required", timeout: 2000,
}});
"""

PAGES = {
    f"{APP}/": "<script>location = 'https://idp.example/login'</script>",
    f"{APP}/home": "<h1>signed in</h1>",
    # A single-page app that only redirects to the IdP after it has loaded.
    f"{APP}/spa": "<script>setTimeout(() => location = 'https://idp.example/login', 800)</script>",
    # Okta Identity Engine style: username first, then the passkey ceremony.
    f"{APP}/cold": "<script>location = 'https://idp.example/identify'</script>",
    f"{IDP}/identify": """<form onsubmit="event.preventDefault();
            if (this.identifier.value === 'someone') location = 'https://idp.example/login';">
        <input name="identifier"><input type="submit" value="Next"></form>""",
    f"{IDP}/enroll": f"""<script>{HELPERS}
        window.enroll = () => navigator.credentials.create({{publicKey: {{
            challenge, rp: {{id: "idp.example", name: "Fake IdP"}},
            user: {{id: b("user-1"), name: "someone", displayName: "Some One"}},
            pubKeyCredParams: [{{type: "public-key", alg: -7}}],
            authenticatorSelection: {{residentKey: "required", userVerification: "required"}},
        }}}}).then(() => {{ location = "https://app.example/home"; }});
        </script>""",
    f"{IDP}/login": f"""<script>{HELPERS}
        assertion().then(() => {{ location = "https://app.example/home"; }},
                         e => {{ document.title = "failed: " + e.name; }});
        </script>""",
    # Asserts, then never lets the user through.
    f"{IDP}/stuck": f"""<script>{HELPERS}
        assertion().then(() => {{ document.title = "asserted"; }});
        </script>""",
    # Asserts, then redirects to a host that is down.
    f"{IDP}/broken-return": f"""<script>{HELPERS}
        assertion().then(() => {{ location = "https://down.example/"; }});
        </script>""",
    # Okta's own account page: with no session it loads, then script sends the
    # browser to the sign-in form (login.harvard.edu does this, seen 2026-10-03).
    f"{IDP}/account-settings/": """<body><script>
        if (document.cookie.includes("sid=1")) {
            document.body.innerHTML = '<h1 data-se="header-fullName">Some One</h1>';
        } else {
            setTimeout(() => location = "https://idp.example/oauth2/authorize", 500);
        }
        </script>""",
    f"{IDP}/oauth2/authorize": f"""<script>{HELPERS}
        assertion().then(() => {{
            document.cookie = "sid=1; path=/; secure";
            location = "https://idp.example/account-settings/";
        }});
        </script>""",
    # Signs in, then the app hops once more from script after it has loaded.
    f"{IDP}/login-hop": f"""<script>{HELPERS}
        assertion().then(() => {{ location = "https://app.example/landing"; }});
        </script>""",
    f"{APP}/landing": "<body><script>setTimeout(() => location = '/home', 300)</script>",
    # Signs in, then the app's own script redirect fails: the browser ends on
    # chrome-error://chromewebdata/ (a 2026-10-14 AWS run reported this as signed in).
    f"{IDP}/login-then-broken": f"""<script>{HELPERS}
        assertion().then(() => {{ location = "https://app.example/leaving"; }});
        </script>""",
    # 350 ms: after the sign-in poll (every 250 ms) has passed, inside settle()'s 500 ms idle wait.
    f"{APP}/leaving": (
        "<body><script>setTimeout(() => location = 'https://down.example/', 350)</script>"
    ),
    f"{APP}/broken-after": "<script>location = 'https://idp.example/login-then-broken'</script>",
    f"{APP}/hop": "<script>location = 'https://idp.example/login-hop'</script>",
    # Retries the passkey on demand, to probe whether the authenticator is gone.
    f"{IDP}/probe": f"""<script>{HELPERS}
        window.probe = () => assertion().then(() => "asserted", e => e.name);
        </script>""",
}


async def serve(route):
    url = route.request.url.split("?")[0]
    if url.startswith(DOWN):
        await route.abort("connectionrefused")
    elif url in PAGES:
        await route.fulfill(status=200, content_type="text/html", body=PAGES[url])
    else:
        await route.fulfill(status=404, body="")


async def launch(p):
    for channel in (None, "chrome"):
        try:
            return await p.chromium.launch(headless=True, channel=channel)
        except PlaywrightError:
            continue
    pytest.skip("no Chromium or Chrome available (run: uv run playwright install chromium)")


async def new_context(browser):
    context = await browser.new_context()
    await context.route("https://*.example/**", serve)
    return context


def fake_settings(tmp_path, **overrides):
    values = {
        "data_dir": tmp_path,
        "rp_id": "idp.example",
        "idp_hosts": ["idp.example"],
        "env": {},
    }
    return Settings.from_env(**{**values, **overrides})


async def enroll(browser, settings):
    """What `register` does after identity proof: attach, create, capture via event."""
    context = await new_context(browser)
    page = await context.new_page()
    await page.goto(f"{IDP}/enroll")
    authn = await VirtualAuthenticator.attach(context, page)
    await page.evaluate("enroll()")
    await page.wait_for_url(f"{APP}/home")  # cross-origin hop right after creation
    assert len(authn.added) == 1
    storage.save_credentials(settings.credential_file, authn.added)
    await authn.detach()
    await context.close()


def sign_count(settings):
    (cred,) = storage.load_credentials(settings.credential_file)
    return cred["signCount"]


def run_with_browser(scenario):
    async def wrapper():
        async with async_playwright() as p:
            browser = await launch(p)
            try:
                await enroll(browser, scenario.settings)
                await scenario(browser)
            finally:
                await browser.close()

    asyncio.run(wrapper())


def scenario_for(settings):
    def decorate(fn):
        fn.settings = settings
        return fn

    return decorate


async def sign_in(browser, settings, url, timeout_s=10):
    return await authenticate(
        browser, settings, url, timeout_s=timeout_s, context=await new_context(browser)
    )


def test_enroll_then_login_twice(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        (cred,) = storage.load_credentials(settings.credential_file)
        assert cred["rpId"] == "idp.example"
        assert cred["userName"] == "someone"
        first = cred["signCount"]
        for expected in (first + 1, first + 2):
            result = await sign_in(browser, settings, f"{APP}/")
            assert result.ok, (result.reason, result.page.url)
            assert result.page.url == f"{APP}/home"
            assert sign_count(settings) == expected
            await result.context.close()

    run_with_browser(scenario)


def test_authenticator_is_removed_after_sign_in(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        result = await sign_in(browser, settings, f"{APP}/")
        assert result.ok
        count = sign_count(settings)
        # Same tab, same origin: a later passkey request must not be answered silently.
        await result.page.goto(f"{IDP}/probe")
        # No authenticator answers. Chrome 154 reports NotAllowedError, Playwright's
        # Chromium 153 NotSupportedError (checked 2026-10-03); "asserted" is the failure.
        assert await result.page.evaluate("probe()") in ("NotAllowedError", "NotSupportedError")
        assert sign_count(settings) == count

    run_with_browser(scenario)


def test_delayed_redirect_is_not_reported_early(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        before = sign_count(settings)
        result = await sign_in(browser, settings, f"{APP}/spa")
        assert result.ok
        assert result.page.url == f"{APP}/home"
        assert sign_count(settings) == before + 1

    run_with_browser(scenario)


def test_sign_count_saved_even_when_sign_in_fails(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        before = sign_count(settings)
        result = await sign_in(browser, settings, f"{IDP}/stuck", timeout_s=3)
        assert not result.ok
        assert "timed out" in result.reason
        assert sign_count(settings) == before + 1

    run_with_browser(scenario)


def test_error_page_is_not_success(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        result = await sign_in(browser, settings, f"{IDP}/broken-return")
        assert not result.ok
        assert "failed to load" in result.reason

    run_with_browser(scenario)


def test_error_page_after_sign_in_is_not_success(tmp_path):
    """Sign-in finished, then a script redirect failed: still a failure, with a reason."""
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        result = await sign_in(browser, settings, f"{APP}/broken-after")
        assert result.page.url.startswith("chrome-error://")
        assert not result.ok
        assert "failed to load" in result.reason

    run_with_browser(scenario)


def test_username_prompt_is_answered(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        # The username comes from the credential (userName saved at enrollment).
        result = await sign_in(browser, settings, f"{APP}/cold")
        assert result.ok, (result.reason, result.page.url)
        assert result.page.url == f"{APP}/home"

    run_with_browser(scenario)


def test_login_moves_a_file_key_into_the_keychain(tmp_path, memory_keyring):
    settings = fake_settings(tmp_path, secret_store="keychain")

    @scenario_for(settings)
    async def scenario(browser):
        (before,) = storage.read_entries(settings.credential_file)
        assert "privateKey" in before  # enroll() saved it the old way, in the file
        for _ in range(2):  # the second run reads the key back from the keychain
            result = await sign_in(browser, settings, f"{APP}/cold")
            assert result.ok, (result.reason, result.page.url)
            await result.context.close()
        (after,) = storage.read_entries(settings.credential_file)
        assert "privateKey" not in after
        assert after["keyStore"] == "keychain"
        assert after["signCount"] > before["signCount"]
        assert len(memory_keyring.items) == 1

    run_with_browser(scenario)


def test_key_moves_even_when_the_passkey_is_not_used(tmp_path, memory_keyring):
    """A page that needs no sign-in never bumps the counter, so only the up-front move runs."""
    settings = fake_settings(tmp_path, secret_store="keychain")

    @scenario_for(settings)
    async def scenario(browser):
        (before,) = storage.read_entries(settings.credential_file)
        storage.save_auth_state(settings.auth_state_file, {"cookies": [], "origins": []})
        result = await sign_in(browser, settings, f"{APP}/home")
        assert result.ok, (result.reason, result.page.url)
        (after,) = storage.read_entries(settings.credential_file)
        assert after["signCount"] == before["signCount"]
        assert "privateKey" not in after
        assert not settings.auth_state_file.exists()  # the session moved too
        assert len(memory_keyring.items) == 2  # the key and the session

    run_with_browser(scenario)


def test_idp_signed_in_page_without_a_session_is_not_success(tmp_path):
    """Okta's account page loads before it redirects to sign-in: not proof of anything."""
    settings = fake_settings(tmp_path, idp_hosts=["idp.example"])

    @scenario_for(settings)
    async def scenario(browser):
        before = sign_count(settings)
        result = await sign_in(browser, settings, f"{IDP}/account-settings/")
        assert result.ok, (result.reason, result.page.url)
        assert sign_count(settings) > before, "returned before the passkey was used"
        await result.page.locator('[data-se="header-fullName"]').wait_for(timeout=5000)

    run_with_browser(scenario)


def test_result_page_has_followed_script_redirects(tmp_path):
    """The page handed back is where the redirects end, not a page about to leave."""
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        hops = []
        result = await authenticate(
            browser,
            settings,
            f"{APP}/hop",
            timeout_s=10,
            context=await new_context(browser),
            on_navigation=hops.append,
        )
        assert result.ok, (result.reason, result.page.url)
        assert result.page.url == f"{APP}/home"
        assert hops == [f"{APP}/hop", f"{IDP}/login-hop", f"{APP}/landing", f"{APP}/home"]

    run_with_browser(scenario)


def test_username_prompt_without_username_fails_fast(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        creds = storage.load_credentials(settings.credential_file)
        del creds[0]["userName"]
        storage.save_credentials(settings.credential_file, creds)

        started = asyncio.get_running_loop().time()
        result = await sign_in(browser, settings, f"{APP}/cold", timeout_s=20)
        assert not result.ok
        assert "username" in result.reason
        assert asyncio.get_running_loop().time() - started < 10

    run_with_browser(scenario)


def test_credential_for_another_rp_is_refused(tmp_path):
    settings = fake_settings(tmp_path)

    @scenario_for(settings)
    async def scenario(browser):
        other = fake_settings(tmp_path, rp_id="someone-else.example")
        with pytest.raises(CredentialFileError, match=r"someone-else\.example"):
            await sign_in(browser, other, f"{APP}/")

    run_with_browser(scenario)


def test_launch_falls_back_to_installed_chrome(capsys):
    """No bundled Chromium: use the installed Chrome instead of failing."""
    from crimson_headless_passkey.flows import launch

    launched = []

    class Chromium:
        async def launch(self, headless, channel=None):
            launched.append(channel)
            if channel is None:
                raise PlaywrightError("Executable doesn't exist at /nowhere/chrome")
            return "browser"

    class FakePlaywright:
        chromium = Chromium()

    assert asyncio.run(launch(FakePlaywright(), headless=True, channel=None)) == "browser"
    assert launched == [None, "chrome"]
    assert "playwright install chromium" in capsys.readouterr().err
    launched.clear()
    asyncio.run(launch(FakePlaywright(), headless=True, channel="msedge"))
    assert launched == ["msedge"]  # an explicit channel is never second-guessed


AWS = "https://d-1234567890.awsapps.com"
AWS_PAGES = {
    f"{AWS}/start/consent": """<button onclick="document.body.innerHTML =
        '<h1>Request approved</h1>'">Allow access</button><button>Deny access</button>""",
    f"{AWS}/start/consent-broken": """<button onclick="location = 'https://down.example/'"
        >Allow access</button>""",
    f"{AWS}/start/consent-silent": """<button onclick="this.disabled = true"
        >Allow access</button>""",
    f"{AWS}/start/no-consent": "<h1>AWS access portal</h1>",
}


def run_aws(path, timeout_s=3):
    """Open a fake AWS consent page (no passkey involved) and run the --aws-allow step."""
    from crimson_headless_passkey.flows import aws_allow_access

    async def go():
        async with async_playwright() as p:
            browser = await launch(p)
            try:
                context = await new_context(browser)

                async def aws(route):
                    body = AWS_PAGES.get(route.request.url.split("?")[0])
                    await route.fulfill(
                        status=200 if body else 404, content_type="text/html", body=body or ""
                    )

                await context.route("https://*.awsapps.com/**", aws)
                page = await context.new_page()
                await page.goto(path)
                result = await aws_allow_access(page, timeout_s=timeout_s)
                return result, page.url, await page.content()
            finally:
                await browser.close()

    return asyncio.run(go())


def test_aws_allow_clicks_allow_and_sees_the_approval():
    (ok, reason), _, content = run_aws(f"{AWS}/start/consent")
    assert ok, reason
    assert "Request approved" in content


def test_aws_allow_fails_when_the_approval_never_appears():
    (ok, reason), _, _ = run_aws(f"{AWS}/start/consent-silent", timeout_s=2)
    assert not ok
    assert "approval page never appeared" in reason


def test_aws_allow_fails_on_an_error_page_after_the_click():
    (ok, reason), url, _ = run_aws(f"{AWS}/start/consent-broken")
    assert url.startswith("chrome-error://")
    assert not ok
    assert "failed to load" in reason


def test_aws_allow_skips_pages_that_are_not_aws_or_have_no_consent(capsys):
    (ok, _), _, _ = run_aws(f"{APP}/home")
    assert ok
    assert "not an AWS access portal page" in capsys.readouterr().out
    (ok, _), _, _ = run_aws(f"{AWS}/start/no-consent", timeout_s=1)
    assert ok
    assert "nothing to approve" in capsys.readouterr().out
