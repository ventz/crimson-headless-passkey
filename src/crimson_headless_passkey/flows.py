"""The three browser flows: register a passkey, log in with it, open a plain browser."""

from __future__ import annotations

import asyncio
import contextlib
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import unquote

from playwright.async_api import Browser, BrowserContext, Frame, Page, Playwright, async_playwright
from playwright.async_api import Error as PlaywrightError

from . import secretstore, storage
from .authenticator import VirtualAuthenticator
from .config import (
    Settings,
    final_url_problem,
    host_of,
    is_idp_url,
    is_secure_url,
    is_signed_in_url,
    redact_url,
)
from .errors import CredentialFileError, LoginPasskeyError, RegistrationError

TROUBLESHOOTING_URL = (
    "https://github.com/ventz/crimson-headless-passkey/blob/main/docs/troubleshooting.md"
)

# Okta Identity Engine's sign-in widget: identifier-first username form.
USERNAME_FIELD = "input[name='identifier']"

# When the page lands off the IdP without ever visiting it (the app had its own
# valid session, or it redirects to the IdP from JavaScript a moment later),
# it must stay on the same URL this long before counting as signed in.
SETTLE_S = 3.0
SETTLE_LIMIT_S = 5  # longest wait for redirects to finish after sign-in or load
POLL_S = 0.25


async def prompt(message: str) -> str:
    """Read a line from stdin without a thread, so Ctrl-C always works.

    input() in a worker thread (asyncio.to_thread, or even a daemon thread)
    keeps the terminal busy, and Ctrl-C at the prompt then hangs while Python
    shuts down. Instead the event loop watches stdin and reads the line once
    it is ready. EOF (no terminal, closed stdin) counts as ENTER.
    """
    print(message, end="", flush=True)
    try:
        fd = sys.stdin.fileno()
    except (AttributeError, ValueError, OSError):
        return ""
    loop = asyncio.get_running_loop()
    future: asyncio.Future[str] = loop.create_future()

    def on_readable() -> None:
        loop.remove_reader(fd)
        if not future.done():
            future.set_result(sys.stdin.readline())

    try:
        loop.add_reader(fd, on_readable)
    except (NotImplementedError, OSError, ValueError):
        # No reader support for this stdin (e.g. Windows): fall back to a thread.
        return (await asyncio.to_thread(sys.stdin.readline)).rstrip("\n")
    try:
        return (await future).rstrip("\n")
    finally:
        loop.remove_reader(fd)


@dataclass
class LoginResult:
    ok: bool
    context: BrowserContext
    page: Page
    # Why sign-in did not finish, when ``ok`` is False.
    reason: str | None = None


def select_credentials(credentials: list[dict], settings: Settings) -> list[dict]:
    """Only credentials for the configured relying party get injected."""
    matching = [c for c in credentials if c["rpId"] == settings.rp_id]
    if not matching:
        found = ", ".join(sorted({c["rpId"] for c in credentials}))
        raise CredentialFileError(
            f"no saved passkey for rpId {settings.rp_id} (found: {found}). "
            "Set --rp-id / CRIMSON_HEADLESS_PASSKEY_RP_ID to match, or register again."
        )
    return matching


async def authenticate(
    browser: Browser,
    settings: Settings,
    url: str,
    *,
    timeout_s: float = 30,
    use_saved_state: bool = True,
    context: BrowserContext | None = None,
    on_navigation: Callable[[str], None] | None = None,
) -> LoginResult:
    """Open ``url`` in a context whose virtual authenticator holds the saved passkey.

    This is the library entry point. It answers Okta's username prompt when one
    appears, waits until sign-in has finished, persists the advanced signCount,
    then removes the virtual authenticator so nothing else in the session can
    use the passkey silently. It returns the context and page for further use;
    the caller owns the browser and closes it.

    Pass ``context`` to bring your own (e.g. with routes or a proxy already
    set); the saved session is only loaded into contexts created here.
    ``on_navigation`` is called with each main-frame URL the page goes
    through, redirects included (``NavigationLog`` prints them for ``-v``).

    Never enable Playwright tracing or ``DEBUG=pw:protocol`` around this call,
    and never use a browser reached through ``connect_over_cdp`` on a debugging
    port: all three expose the private key.
    """
    if browser.browser_type.name != "chromium":
        raise LoginPasskeyError("virtual authenticators need a Chromium-based browser")

    with storage.locked(settings.data_dir):
        credentials = storage.load_credentials(settings.credential_file)
        move_secrets(settings, credentials)
        selected = select_credentials(credentials, settings)
        owns_context = context is None
        if context is None:
            state = (
                storage.load_auth_state(settings.auth_state_file, settings.secret_store)
                if use_saved_state
                else None
            )
            context = await browser.new_context(storage_state=state)
        try:
            page = await context.new_page()
            if on_navigation:
                watch_navigation(page, on_navigation)
            page.set_default_timeout(timeout_s * 1000)
            # Before navigation: the credential has to be in place when the IdP asks.
            authn = await VirtualAuthenticator.attach(context, page)
            try:
                for cred in selected:
                    await authn.add_credential(cred)
                username = (
                    settings.username
                    or next((c["userName"] for c in selected if c.get("userName")), None)
                    or await remembered_username(context, settings.idp_hosts)
                )
                await page.goto(url)
                ok, reason = await wait_for_sign_in(page, settings, authn, username, timeout_s)
            finally:
                await persist_sign_counts(settings, credentials, authn)
                await authn.detach()
        except BaseException:
            if owns_context:
                with contextlib.suppress(Exception):
                    await context.close()
            raise

    if ok:
        await settle(page)
        # A script redirect after sign-in can still fail and leave the browser
        # on its error page; that is never success (constraint 5).
        if problem := final_url_problem(page.url):
            ok, reason = False, problem
    return LoginResult(ok=ok, context=context, page=page, reason=reason)


def watch_navigation(page: Page, callback: Callable[[str], None]) -> None:
    """Call ``callback`` with every main-frame URL ``page`` lands on."""
    page.on("framenavigated", lambda frame: frame == page.main_frame and callback(frame.url))


class NavigationLog:
    """Prints each hop of a redirect chain for ``-v``, with query strings hidden.

    Consecutive repeats of the same URL (single-page apps re-announce it) are
    shown once.
    """

    def __init__(self, out: TextIO | None = None) -> None:
        self.out = out  # None: stdout, looked up at print time, in order with the rest
        self.started = time.monotonic()
        self.last: str | None = None

    def __call__(self, url: str) -> None:
        shown = redact_url(url)
        if shown == self.last:
            return
        self.last = shown
        elapsed = time.monotonic() - self.started
        print(f"  -> {elapsed:5.2f}s  {shown}", file=self.out or sys.stdout, flush=True)


async def settle(page: Page, timeout_s: float = SETTLE_LIMIT_S) -> None:
    """Let script redirects finish before anyone reads the URL or the page.

    Many redirects run from script after the page has loaded: Okta's own pages
    move to the next step about 0.6 s later (seen 2026-10-03). Waiting for the
    network to go quiet follows them. Pages that never go quiet (long polling)
    just use up the time limit.
    """
    with contextlib.suppress(PlaywrightError):
        await page.wait_for_load_state("networkidle", timeout=timeout_s * 1000)


async def persist_sign_counts(
    settings: Settings, credentials: list[dict], authn: VirtualAuthenticator
) -> None:
    """Save the advanced counter, even when sign-in did not finish.

    Each assertion bumps the counter on the IdP side too, so the next run must
    never present an older count. A failure here is reported but does not hide
    the error that got us here.
    """
    try:
        counts = await authn.current_sign_counts()
        if storage.apply_sign_counts(credentials, counts):
            storage.save_credentials(settings.credential_file, credentials, settings.secret_store)
    except Exception as e:
        print(f"warning: could not save the sign counter: {e}", file=sys.stderr)


def secrets_location(settings: Settings, path: Path) -> str:
    return "the keychain" if settings.secret_store == secretstore.KEYCHAIN else str(path)


def move_secrets(settings: Settings, credentials: list[dict]) -> None:
    """Move the private key and saved session into the configured secret store.

    Runs at the start of every sign-in, not only when the counter is saved: a
    still-valid session skips the passkey, and then the counter never moves.
    """
    if any(c["keyStore"] != settings.secret_store for c in credentials):
        storage.save_credentials(settings.credential_file, credentials, settings.secret_store)
        where = secrets_location(settings, settings.credential_file)
        print(f"Moved the private key to {where}.", file=sys.stderr)
    if storage.move_auth_state(settings.auth_state_file, settings.secret_store):
        where = secrets_location(settings, settings.auth_state_file)
        print(f"Moved the saved session to {where}.", file=sys.stderr)


async def remembered_username(context: BrowserContext, idp_hosts: tuple[str, ...]) -> str | None:
    """The username Okta remembered in its ``ln`` cookie, if the saved session has one.

    Only cookies set for an IdP host itself count: Playwright reports host-only
    cookies without a leading dot and domain cookies with one, and a cookie for
    a parent domain (``.harvard.edu``) is ignored.
    """
    for cookie in await context.cookies():
        if cookie["name"] == "ln" and cookie["domain"].lstrip(".").lower() in idp_hosts:
            return unquote(cookie["value"]) or None
    return None


async def wait_for_sign_in(
    page: Page,
    settings: Settings,
    authn: VirtualAuthenticator,
    username: str | None,
    timeout_s: float,
) -> tuple[bool, str | None]:
    """Poll until signed in, submitting the username once if Okta asks for it.

    A destination-looking URL is not enough on its own: an app's first page
    looks the same before its redirect to the IdP. Success needs evidence: an
    IdP sign-in page was shown during this run, a passkey assertion happened,
    or the page stayed on the same URL for SETTLE_S.

    Only an IdP page that is not itself a destination counts as a sign-in
    page. Okta's own signed-in pages load first and redirect to the sign-in
    form from script when there is no session (``/account-settings/`` goes to
    ``/oauth2/v1/authorize`` about 0.6 s later, seen 2026-10-03), so landing on
    one is not evidence of anything.
    """
    hosts = settings.idp_hosts

    def is_sign_in_page(url: str) -> bool:
        return is_idp_url(url, hosts) and not is_signed_in_url(url, hosts)

    seen_sign_in = is_sign_in_page(page.url)

    def on_navigated(frame: Frame) -> None:
        nonlocal seen_sign_in
        if frame == page.main_frame and is_sign_in_page(frame.url):
            seen_sign_in = True

    page.on("framenavigated", on_navigated)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    submitted = False
    settling: tuple[str, float] | None = None
    try:
        while loop.time() < deadline:
            url = page.url
            if url.startswith("chrome-error://"):
                return False, "the page failed to load (network error)"
            if is_signed_in_url(url, hosts):
                if seen_sign_in or authn.sign_counts:
                    return True, None
                if settling is None or settling[0] != url:
                    settling = (url, loop.time())
                elif loop.time() - settling[1] >= SETTLE_S:
                    return True, None
            else:
                settling = None
                seen_sign_in = seen_sign_in or is_sign_in_page(url)
                if not submitted and is_idp_url(url, hosts) and is_secure_url(url):
                    outcome = await submit_username(page, url, username)
                    if outcome == "missing":
                        return False, (
                            "Okta is asking for a username; pass --username or set "
                            "CRIMSON_HEADLESS_PASSKEY_USERNAME"
                        )
                    submitted = outcome == "submitted"
            await asyncio.sleep(POLL_S)
        return False, f"timed out after {timeout_s:g}s"
    finally:
        page.remove_listener("framenavigated", on_navigated)


async def submit_username(page: Page, url: str, username: str | None) -> str:
    """Fill Okta's username field if it is showing. Returns absent, missing or submitted.

    The element handle is bound to the current document: if the page navigates
    away in between, filling it raises instead of typing into the next page.
    """
    try:
        field = await page.query_selector(USERNAME_FIELD)
        if field is None or not await field.is_visible():
            return "absent"
        if not username:
            return "missing"
        if page.url != url:
            return "absent"
        await field.fill(username)
        # The submit button of the username's own form, not any form on the page.
        button = await field.evaluate_handle(
            "el => el.form && el.form.querySelector('[type=submit]')"
        )
        element = button.as_element()
        if element is None:
            return "absent"
        await element.click()
    except PlaywrightError:
        return "absent"  # navigated mid-fill; look again on the next poll
    return "submitted"


async def close_quietly(browser: Browser) -> None:
    """Close the browser without masking the real error (or Ctrl-C) with a close error."""
    with contextlib.suppress(Exception):
        await browser.close()


async def launch(p: Playwright, *, headless: bool, channel: str | None) -> Browser:
    """Launch Chromium. With no channel, use installed Chrome if Playwright's is missing."""
    if channel is not None:
        return await p.chromium.launch(headless=headless, channel=channel)
    try:
        return await p.chromium.launch(headless=headless)
    except PlaywrightError as e:
        if "Executable doesn't exist" not in str(e):
            raise
    print(
        "Playwright's Chromium is not installed, so using your installed Google Chrome. "
        "(To install it: uv run playwright install chromium)",
        file=sys.stderr,
    )
    return await p.chromium.launch(headless=headless, channel="chrome")


async def login(
    settings: Settings,
    url: str,
    *,
    headless: bool = False,
    channel: str | None = None,
    timeout_s: float = 30,
    use_saved_state: bool = True,
    save_state: bool = True,
    keep_open: bool = False,
    verbose: bool = False,
    aws_allow: bool = False,
) -> bool:
    # Fail on a missing or unsafe credential before starting a browser.
    select_credentials(storage.load_credentials(settings.credential_file), settings)
    async with async_playwright() as p:
        browser = await launch(p, headless=headless, channel=channel)
        try:
            print(f"Navigating to {redact_url(url)} ...", flush=True)
            result = await authenticate(
                browser,
                settings,
                url,
                timeout_s=timeout_s,
                use_saved_state=use_saved_state,
                on_navigation=NavigationLog() if verbose else None,
            )
            ok, reason = result.ok, result.reason
            if ok and (problem := final_url_problem(result.page.url)):
                ok, reason = False, problem  # belt and braces: never save an error page
            if ok and aws_allow:
                ok, reason = await aws_allow_access(result.page, timeout_s=timeout_s)
            if ok:
                print(f"Signed in. Current URL: {redact_url(result.page.url)}")
                if save_state:
                    state = await result.context.storage_state()
                    storage.save_auth_state(settings.auth_state_file, state, settings.secret_store)
                    print(
                        f"Session saved to {secrets_location(settings, settings.auth_state_file)}"
                    )
            else:
                print(f"Sign-in did not finish: {reason}.")
                print(f"Current URL: {redact_url(result.page.url)}")
                print(f"The saved session was left unchanged. See {TROUBLESHOOTING_URL}")
            if keep_open:
                await prompt("\nBrowser is open. Press ENTER to close. ")
            return ok
        finally:
            await close_quietly(browser)


# AWS IAM Identity Center access portals: the classic *.awsapps.com and the
# newer *.app.aws hosts.
AWS_PORTAL_SUFFIXES = (".awsapps.com", ".app.aws")
AWS_ALLOW_BUTTON = re.compile(r"^\s*allow( access)?\s*$", re.IGNORECASE)
AWS_APPROVED_TEXT = re.compile(r"request approved|access (was )?(approved|granted)", re.IGNORECASE)


def is_aws_portal_url(url: str) -> bool:
    host = host_of(url)
    return is_secure_url(url) and any(host.endswith(s) for s in AWS_PORTAL_SUFFIXES)


async def aws_allow_access(page: Page, *, timeout_s: float = 30) -> tuple[bool, str | None]:
    """After sign-in, approve AWS IAM Identity Center's "Allow access" consent page.

    Opt-in (``--aws-allow``): clicking Allow hands AWS tokens to whichever
    client started the request (``aws sso login``, or a phished device code),
    so it only happens when asked for. Success needs the approval page, not
    just the click. No consent page within the timeout is not an error: AWS
    skips it when the client was already approved.
    """
    deadline = asyncio.get_running_loop().time() + timeout_s
    button = page.get_by_role("button", name=AWS_ALLOW_BUTTON)
    while True:
        if problem := final_url_problem(page.url):
            return False, problem
        if not is_aws_portal_url(page.url):
            print(f"--aws-allow: not an AWS access portal page ({redact_url(page.url)}); skipped.")
            return True, None
        with contextlib.suppress(PlaywrightError):
            if await button.first.is_visible():
                break
        if asyncio.get_running_loop().time() >= deadline:
            print('--aws-allow: no "Allow access" button appeared; nothing to approve.')
            return True, None
        await asyncio.sleep(POLL_S)

    await button.first.click()
    print('--aws-allow: clicked "Allow access".')
    approved = page.get_by_text(AWS_APPROVED_TEXT)
    while asyncio.get_running_loop().time() < deadline:
        if problem := final_url_problem(page.url):
            return False, f"after Allow access, {problem}"
        with contextlib.suppress(PlaywrightError):
            if await approved.first.is_visible():
                print("--aws-allow: AWS shows the request as approved.")
                return True, None
        await asyncio.sleep(POLL_S)
    return False, "clicked Allow access, but the AWS approval page never appeared"


def quit_system_chrome() -> None:
    """Ask a running Google Chrome to quit (macOS only). Unsaved Chrome state is lost."""
    if sys.platform != "darwin":
        print("--quit-chrome only works on macOS; skipping.")
        return
    subprocess.run(
        ["osascript", "-e", 'tell application "Google Chrome" to quit'],
        capture_output=True,
        check=False,
    )


REGISTER_INSTRUCTIONS = """
============================================================
PHASE 1: Verify your identity the normal way (e.g. Touch ID)
============================================================
1. Sign in with your existing passkey, security key or app.
2. Open your Okta security settings and choose "Set up" for
   another "Security Key or Biometric" (NOT Okta FastPass).
3. If Okta asks you to verify again, do it the normal way.
4. STOP at the enrollment screen ("Set up security key" /
   "Use passkey"). Do NOT click its button yet.

Press ENTER here right BEFORE clicking the enrollment button.
============================================================
"""


def enrollment_page(context: BrowserContext, settings: Settings) -> Page | None:
    """The most recent tab on an IdP host, else the most recent tab."""
    pages = [p for p in context.pages if not p.is_closed()]
    on_idp = [p for p in pages if is_idp_url(p.url, settings.idp_hosts)]
    return (on_idp or pages or [None])[-1]


async def register(
    settings: Settings,
    *,
    force: bool = False,
    channel: str | None = "chrome",
    quit_chrome: bool = False,
) -> None:
    """Interactive: real login for identity proof, then a virtual passkey enrollment."""
    if settings.credential_file.exists() and not force:
        raise RegistrationError(
            f"{settings.credential_file} already exists. Pass --force to replace it, "
            "then remove the old passkey in your Okta security settings: replacing "
            "the file does not revoke it."
        )
    storage.ensure_private_dir(settings.data_dir)
    replaced = (
        storage.read_entries(settings.credential_file)
        if force and settings.credential_file.exists()
        else []
    )
    if quit_chrome:
        quit_system_chrome()
        await asyncio.sleep(2)

    async with async_playwright() as p:
        # System Chrome, because Playwright's bundled Chromium cannot use
        # Touch ID or iCloud Keychain for the phase-1 sign-in.
        browser = await p.chromium.launch(headless=False, channel=channel)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(settings.login_url)
            print(f"\nOpened {settings.login_url}")
            print(REGISTER_INSTRUCTIONS)
            await prompt("Press ENTER to activate the virtual authenticator... ")

            page = enrollment_page(context, settings)
            if page is None:
                raise RegistrationError("the browser window was closed")
            authn = await VirtualAuthenticator.attach(context, page)
            try:
                print(f"\nVirtual authenticator active on {redact_url(page.url)}")
                print("Now click the enrollment button in the browser.")
                print("The virtual authenticator answers it; no Touch ID needed.")
                await prompt("\nPress ENTER once Okta shows the enrollment succeeded... ")

                captured = list(authn.added)
                if not captured:
                    try:
                        captured = await authn.get_credentials()
                    except PlaywrightError:  # session may be gone after the IdP navigated
                        captured = []
            finally:
                await authn.detach()
            if not captured:
                raise RegistrationError(
                    "No credential was created. Make sure you pressed ENTER before "
                    "clicking the enrollment button, then run register again."
                )

            credentials = [storage.credential_from_cdp(c) for c in captured]
            for cred in credentials:
                print(
                    f"  captured passkey for rpId {cred['rpId']} "
                    f"(credentialId {cred['credentialId'][:16]}...)"
                )
            matching = [c for c in credentials if c["rpId"] == settings.rp_id]
            if not matching:
                raise RegistrationError(
                    f"none of the captured passkeys is for rpId {settings.rp_id}. Remove "
                    "the new authenticator in Okta, then rerun register with --rp-id set "
                    "to the rpId printed above."
                )

            storage.save_credentials(settings.credential_file, matching, settings.secret_store)
            storage.forget_keys(replaced, keep=matching)
            if settings.secret_store == secretstore.KEYCHAIN:
                print(f"\nPrivate key saved to the keychain (service {secretstore.SERVICE!r})")
            print(f"Credential saved to {settings.credential_file}")
            storage.save_auth_state(
                settings.auth_state_file, await context.storage_state(), settings.secret_store
            )
            print(f"Session saved to {secrets_location(settings, settings.auth_state_file)}")
            print("\nDone. Run `crimson-headless-passkey login` to sign in automatically.")
        finally:
            await close_quietly(browser)


async def open_url(url: str, *, channel: str | None = None, verbose: bool = False) -> None:
    """A plain browser with no passkey and no saved session, for comparison and demos."""
    async with async_playwright() as p:
        browser = await launch(p, headless=False, channel=channel)
        try:
            page = await browser.new_page()
            print(f"Navigating to {redact_url(url)} ...", flush=True)
            if verbose:
                watch_navigation(page, NavigationLog())
            await page.goto(url)
            await settle(page)
            print(f"Current URL: {redact_url(page.url)}")
            await prompt("\nBrowser is open. Press ENTER to close. ")
        finally:
            await close_quietly(browser)
