"""Okta chooser / banners and Microsoft KMSI / loginfmt, against fake pages."""

from __future__ import annotations

import asyncio

import pytest
from playwright.async_api import async_playwright

from crimson_headless_passkey import okta
from crimson_headless_passkey.exitcodes import STATUS_AUTH_FAILED, STATUS_NEEDS_HUMAN

pytestmark = pytest.mark.browser

IDP = "https://idp.example"
SSO = "https://login.microsoftonline.com"

PAGES = {
    f"{IDP}/chooser": """
        <div data-se="authenticator-verify-list">
          <div class="authenticator-row" data-se="okta_verify">Okta Verify</div>
          <div class="authenticator-row" data-se="webauthn">
            <a data-se="authenticator-button" href="#pk">Security Key or Biometric</a>
          </div>
        </div>""",
    f"{IDP}/chooser-no-passkey": """
        <div data-se="authenticator-verify-list">
          <div class="authenticator-row" data-se="okta_verify">Okta Verify</div>
          <div class="authenticator-row" data-se="phone">Phone</div>
        </div>""",
    f"{IDP}/banner": """
        <div class="o-form-error-container">
          <div role="alert" class="infobox-error">Unable to sign in</div>
        </div>""",
    f"{IDP}/banner-push": """
        <div class="o-form-error-container">
          <div role="alert">Approve the push notification in Okta Verify</div>
        </div>""",
    f"{SSO}/loginfmt": """
        <form><input name="loginfmt" id="i0116">
        <input type="submit" id="idSIButton9" value="Next"
               onclick="document.title = 'picked ' + this.form.loginfmt.value; return false">
        </form>""",
    # Microsoft's username page also carries an off-screen, aria-hidden,
    # tabindex=-1 password input for browser autofill. Playwright's is_visible()
    # reports it as visible, which 0.3.0 misread as a password prompt (exit 3).
    f"{SSO}/username-prefill": """
        <style>.moveOffScreen{position:fixed;bottom:0;right:0;height:0!important;
          width:0!important;overflow:hidden;opacity:0}</style>
        <form><input name="loginfmt" id="i0116">
        <input type="password" name="passwd" class="moveOffScreen" tabindex="-1"
               aria-hidden="true">
        <input type="submit" id="idSIButton9" value="Next"
               onclick="document.title = 'picked ' + this.form.loginfmt.value; return false">
        </form>""",
    # Home realm discovery: the password view flashes, then the federated
    # account is redirected to the IdP.
    f"{SSO}/hrd-flash": """
        <input type="password" name="passwd" id="i0118">
        <script>setTimeout(() => location.href = "https://idp.example/federated", 700)</script>""",
    f"{IDP}/federated": "<p>IdP sign-in</p>",
    f"{SSO}/password": """
        <input type="password" name="passwd" id="i0118">
        <button id="idSIButton9">Sign in</button>""",
    f"{SSO}/approve": """
        <div id="idDiv_SAOTCAS_Title">Approve sign in request</div>""",
    f"{SSO}/kmsi": """
        <div id="KmsiDescription">Stay signed in?</div>
        <button id="idSIButton9">Yes</button>
        <button id="idBtn_Back" onclick="document.title='kmsi-no'">No</button>""",
}


async def open_page(path: str):
    p = await async_playwright().start()
    browser = await p.chromium.launch(headless=True)
    context = await browser.new_context()

    async def serve(route):
        url = route.request.url.split("?")[0]
        body = PAGES.get(url, "")
        await route.fulfill(status=200 if body else 404, content_type="text/html", body=body)

    await context.route("https://**/*", serve)
    page = await context.new_page()
    await page.goto(path)
    return p, browser, page


def run(coro):
    return asyncio.run(coro)


def test_chooser_clicks_passkey_option():
    async def go():
        p, browser, page = await open_page(f"{IDP}/chooser")
        try:
            handler = okta.IdpPageHandler(("idp.example",), (), None)
            step = await handler.inspect(page)
            assert step.kind == "acted"
            # Second poll on the same URL is a no-op (once).
            assert (await handler.inspect(page)).kind == "none"
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_chooser_without_passkey_needs_human():
    async def go():
        p, browser, page = await open_page(f"{IDP}/chooser-no-passkey")
        try:
            handler = okta.IdpPageHandler(("idp.example",), (), None)
            step = await handler.inspect(page)
            assert step.kind == STATUS_NEEDS_HUMAN
            assert "no Security Key" in step.reason
            assert "Okta Verify" in step.reason
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_error_banner_is_auth_failed():
    async def go():
        p, browser, page = await open_page(f"{IDP}/banner")
        try:
            step = await okta.IdpPageHandler(("idp.example",), (), None).inspect(page)
            assert step.kind == STATUS_AUTH_FAILED
            assert "Unable to sign in" in step.reason
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_push_banner_needs_human():
    async def go():
        p, browser, page = await open_page(f"{IDP}/banner-push")
        try:
            step = await okta.IdpPageHandler(("idp.example",), (), None).inspect(page)
            assert step.kind == STATUS_NEEDS_HUMAN
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_microsoft_loginfmt_uses_upn():
    async def go():
        p, browser, page = await open_page(f"{SSO}/loginfmt")
        try:
            handler = okta.IdpPageHandler((), ("login.microsoftonline.com",), "a@harvard.edu")
            step = await handler.inspect(page)
            assert step.kind == "acted"
            await page.wait_for_function("document.title.startsWith('picked')")
            assert "a@harvard.edu" in await page.title()
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_microsoft_kmsi_answers_no():
    async def go():
        p, browser, page = await open_page(f"{SSO}/kmsi")
        try:
            handler = okta.IdpPageHandler((), ("login.microsoftonline.com",), "a@harvard.edu")
            step = await handler.inspect(page)
            assert step.kind == "acted"
            await page.wait_for_function("document.title === 'kmsi-no'")
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_microsoft_offscreen_password_prefill_is_not_a_prompt():
    """Reproduces the 2026-10-20 exit 3: the hidden autofill field must not count."""

    async def go():
        p, browser, page = await open_page(f"{SSO}/username-prefill")
        try:
            assert await page.locator('input[name="passwd"]').is_visible()  # the trap
            handler = okta.IdpPageHandler((), ("login.microsoftonline.com",), "a@harvard.edu")
            step = await handler.inspect(page)
            assert step.kind == "acted", step
            await page.wait_for_function("document.title.startsWith('picked')")
            assert "a@harvard.edu" in await page.title()
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_microsoft_password_flash_before_federation_is_not_terminal():
    """A password view that gives way to the IdP redirect never ends the sign-in."""

    async def go():
        p, browser, page = await open_page(f"{SSO}/hrd-flash")
        try:
            handler = okta.IdpPageHandler((), ("login.microsoftonline.com",), "a@harvard.edu")
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 5
            while "idp.example" not in page.url and loop.time() < deadline:
                step = await handler.inspect(page)
                assert not step.terminal, f"misread the federation hop: {step}"
                await asyncio.sleep(0.25)
            assert page.url.startswith("https://idp.example/federated")
        finally:
            await browser.close()
            await p.stop()

    run(go())


@pytest.mark.parametrize("path", ["password", "approve"])
def test_microsoft_real_password_or_approval_needs_human_after_settle(path):
    async def go():
        p, browser, page = await open_page(f"{SSO}/{path}")
        try:
            handler = okta.IdpPageHandler(
                (), ("login.microsoftonline.com",), "a@harvard.edu", human_settle_s=0.5
            )
            first = await handler.inspect(page)
            assert first.kind == "none"  # not yet: could be the federation flash
            await asyncio.sleep(0.6)
            step = await handler.inspect(page)
            assert step.kind == STATUS_NEEDS_HUMAN
            assert "password or MFA" in (step.reason or "")
        finally:
            await browser.close()
            await p.stop()

    run(go())


def test_classify_banner_helpers():
    assert okta.classify_banner("Unable to sign in").kind == STATUS_AUTH_FAILED
    assert okta.classify_banner("Enter the code from Okta Verify").kind == STATUS_NEEDS_HUMAN
