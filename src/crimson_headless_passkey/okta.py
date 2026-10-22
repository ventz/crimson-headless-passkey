"""Okta's authenticator chooser and error banners, and Microsoft's sign-in hops.

Called from ``flows.wait_for_sign_in`` on every poll while the browser is on a
signing-in host. One DOM snapshot per poll (a single ``evaluate``) decides:

- **Okta error banner** -> auth failed (1), or needs a human (3) when the text
  asks for Okta Verify, a push, a code or a phone.
- **Okta authenticator chooser** -> click the "Security Key or Biometric"
  (WebAuthn) option once; no such option -> needs a human (3).
- **CAPTCHA** -> needs a human (3). Never solved or evaded (CLAUDE.md, NYT).
- **Microsoft "Pick an account" / loginfmt** -> type the UPN (``--upn``, default
  the HarvardKey username) once, on a configured SSO host only.
- **Microsoft "Stay signed in?" (KMSI)** -> answer **No** (reviewer decision
  2026-10-20: no longer-lived Microsoft session).
- **Microsoft error or MFA/password prompt** -> auth failed / needs a human.

SELECTORS ARE UNVERIFIED against the real tenant (HarvardKey never shows this
account a chooser; Microsoft hops not yet observed). They live in the tables
below so one edit fixes them; the offline fake-IdP pages in tests/test_okta.py
mirror them. Banner text is redacted before it reaches ``reason``.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from . import redact
from .config import host_of
from .exitcodes import STATUS_AUTH_FAILED, STATUS_NEEDS_HUMAN

# Okta Identity Engine sign-in widget (Gen2 and Gen3 class names).
OKTA_CHOOSER = (
    '[data-se="authenticator-verify-list"]',
    ".authenticator-verify-list",
    '[data-se="authenticator-select-list"]',
)
OKTA_PASSKEY_OPTION = (
    '[data-se="webauthn"]',
    '[data-se-key="webauthn"]',
    '[data-se="authenticator-button"][data-se-authenticator="webauthn"]',
)
# Fallback: a chooser row whose label names the passkey authenticator.
PASSKEY_LABEL = re.compile(r"security key or biometric|passkey|webauthn", re.IGNORECASE)
OKTA_BANNER = (
    '.o-form-error-container [role="alert"]',
    ".o-form-error-container .infobox-error",
    ".okta-form-infobox-error",
    '[data-se="callout"].infobox-error',
    '[data-se="o-form-error-container"] [role="alert"]',
)
CAPTCHA = ('iframe[src*="captcha"]', ".g-recaptcha", ".h-captcha", "#captcha-container")

# Microsoft Entra ID.
MS_LOGINFMT = 'input[name="loginfmt"]'
MS_NEXT = "#idSIButton9"
MS_KMSI_MARKERS = ("#KmsiCheckboxField", "#KmsiDescription", '[data-testid="kmsiVideo"]')
MS_KMSI_NO = "#idBtn_Back"
MS_ERROR = ("#usernameError", "#passwordError", "#service_exception_message", "#errorText")
MS_HUMAN = ('input[name="passwd"]', "#idDiv_SAOTCAS_Title", "#idDiv_SAOTCC_Title")
# A password/MFA prompt must hold this long on the same page before it is final.
# Microsoft's home realm discovery can flash its password view for a moment
# before redirecting a federated account to the IdP (diagnosed 2026-10-20).
MS_HUMAN_SETTLE_S = 2.5

# True only for a prompt a person could actually use. Playwright's is_visible()
# counts opacity:0, zero-size-with-border and off-screen fields as visible, and
# Microsoft's username page carries an off-screen, aria-hidden, tabindex=-1
# password input (browser autofill prefill). That field must not count.
REAL_PROMPT_JS = """
(el) => {
  if (!el || !el.isConnected) return false;
  if (el.closest('[aria-hidden="true"], [hidden], .moveOffScreen')) return false;
  if (el.matches('input') && (el.disabled || el.readOnly || el.tabIndex < 0)) return false;
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    const cs = getComputedStyle(n);
    if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0)
      return false;
  }
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) return false;
  return r.right > 0 && r.bottom > 0 &&
      r.left < (window.innerWidth || 0) && r.top < (window.innerHeight || 0);
}
"""

HUMAN_TEXT = re.compile(
    r"okta verify|push notification|verification code|enter (the )?code|phone|sms|"
    r"number challenge|approve (the )?(sign.?in|request)|captcha",
    re.IGNORECASE,
)

SNAPSHOT_JS = """
([chooser, passkey, label, banner, captcha]) => {
  const vis = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const first = sels => sels.map(s => document.querySelector(s)).find(vis) || null;
  const out = {banner: null, chooser: false, passkey: false, options: [], captcha: false};
  const b = first(banner);
  if (b) out.banner = (b.innerText || b.textContent || "").trim().slice(0, 300);
  const list = first(chooser);
  if (list) {
    out.chooser = true;
    const rx = new RegExp(label, "i");
    const rows = Array.from(list.querySelectorAll(
        '[data-se], .authenticator-row, button, a, [role="button"]'));
    out.options = Array.from(new Set(rows.map(r => (r.innerText || "").trim().split("\\n")[0])
        .filter(Boolean))).slice(0, 12);
    out.passkey = passkey.some(s => vis(list.querySelector(s))) ||
        rows.some(r => vis(r) && rx.test(r.innerText || ""));
  }
  out.captcha = !!first(captcha);
  return out;
}
"""


@dataclass(frozen=True)
class Step:
    """What the IdP page needs. ``kind``: none, acted, needs_human or auth_failed."""

    kind: str
    reason: str | None = None

    @property
    def terminal(self) -> bool:
        return self.kind in (STATUS_NEEDS_HUMAN, STATUS_AUTH_FAILED)


NOTHING = Step("none")
ACTED = Step("acted")


def classify_banner(text: str) -> Step:
    shown = redact.redact_text(" ".join(text.split()))
    if HUMAN_TEXT.search(text):
        return Step(STATUS_NEEDS_HUMAN, f"Okta needs a person: {shown}")
    return Step(STATUS_AUTH_FAILED, f"Okta reported an error: {shown}")


class IdpPageHandler:
    """Per-sign-in state, so each action happens at most once per page URL."""

    def __init__(
        self,
        idp_hosts: tuple[str, ...],
        sso_hosts: tuple[str, ...],
        upn: str | None,
        *,
        human_settle_s: float = MS_HUMAN_SETTLE_S,
    ):
        self.idp_hosts = {h.lower() for h in idp_hosts}
        self.sso_hosts = {h.lower() for h in sso_hosts}
        self.upn = upn
        self.done: set[tuple[str, str]] = set()
        self.human_settle_s = human_settle_s
        # (page key, selector) -> first time a real password/MFA prompt was seen.
        self._human_since: dict[tuple[str, str], float] = {}

    async def inspect(self, page: Page) -> Step:
        url = page.url
        host = host_of(url)
        try:
            if host in self.idp_hosts:
                return await self._okta(page, url)
            if host in self.sso_hosts:
                return await self._microsoft(page, url)
        except PlaywrightError:
            return NOTHING  # navigated mid-inspection; look again next poll
        return NOTHING

    def _once(self, url: str, action: str) -> bool:
        key = (url.split("#", 1)[0].split("?", 1)[0], action)
        if key in self.done:
            return False
        self.done.add(key)
        return True

    async def _okta(self, page: Page, url: str) -> Step:
        snap = await page.evaluate(
            SNAPSHOT_JS,
            [
                list(OKTA_CHOOSER),
                list(OKTA_PASSKEY_OPTION),
                PASSKEY_LABEL.pattern,
                list(OKTA_BANNER),
                list(CAPTCHA),
            ],
        )
        if snap["banner"]:
            return classify_banner(snap["banner"])
        if snap["captcha"]:
            return Step(STATUS_NEEDS_HUMAN, "the sign-in page shows a CAPTCHA")
        if snap["chooser"]:
            if not snap["passkey"]:
                offered = ", ".join(redact.redact_text(o) for o in snap["options"]) or "none"
                return Step(
                    STATUS_NEEDS_HUMAN,
                    "Okta's authenticator chooser has no Security Key or Biometric option "
                    f"(offered: {offered})",
                )
            if self._once(url, "chooser") and await self._click_passkey(page):
                return ACTED
        return NOTHING

    async def _click_passkey(self, page: Page) -> bool:
        for chooser in OKTA_CHOOSER:
            root = page.locator(chooser).first
            if not await root.count() or not await root.is_visible():
                continue
            for sel in OKTA_PASSKEY_OPTION:
                option = root.locator(sel).first
                if await option.count() and await option.is_visible():
                    await _click_option(option)
                    return True
            row = root.locator(".authenticator-row, [data-se], li").filter(has_text=PASSKEY_LABEL)
            if await row.count():
                await _click_option(row.first)
                return True
        return False

    async def _microsoft(self, page: Page, url: str) -> Step:
        for sel in MS_ERROR:
            el = page.locator(sel).first
            if await el.count() and await el.is_visible():
                text = redact.redact_text(" ".join((await el.inner_text()).split()))
                return Step(STATUS_AUTH_FAILED, f"Microsoft sign-in reported an error: {text}")
        human = await self._real_human_prompt(page)
        if human is None:
            self._human_since.clear()
        else:
            key = (url.split("#", 1)[0].split("?", 1)[0], human)
            now = asyncio.get_running_loop().time()
            since = self._human_since.setdefault(key, now)
            if now - since >= self.human_settle_s:
                return Step(
                    STATUS_NEEDS_HUMAN,
                    "Microsoft is asking for a password or MFA approval instead of "
                    "federating to the configured IdP",
                )
            return NOTHING  # may be the brief flash before the federation redirect
        for sel in MS_KMSI_MARKERS:
            el = page.locator(sel).first
            if await el.count() and await el.is_visible():
                no = page.locator(MS_KMSI_NO).first
                if self._once(url, "kmsi") and await no.count():
                    await no.click()  # "Stay signed in?" -> No (decided 2026-10-20)
                    return ACTED
                return NOTHING
        field = page.locator(MS_LOGINFMT).first
        if await field.count() and await field.is_visible():
            if not self.upn:
                return Step(
                    STATUS_NEEDS_HUMAN,
                    "Microsoft is asking which account to use; pass --upn or set "
                    "CRIMSON_HEADLESS_PASSKEY_UPN (default: the HarvardKey username)",
                )
            if self._once(url, "loginfmt"):
                await field.fill(self.upn)
                button = page.locator(MS_NEXT).first
                if await button.count():
                    await button.click()
                else:
                    await field.press("Enter")
                return ACTED
        return NOTHING

    async def _real_human_prompt(self, page: Page) -> str | None:
        """The first MS_HUMAN selector that is a real, usable prompt, else None."""
        for sel in MS_HUMAN:
            for el in await page.locator(sel).all():
                if await el.evaluate(REAL_PROMPT_JS):
                    return sel
        return None


async def _click_option(option) -> None:
    """Click the option's own button if it has one, else the option itself."""
    inner = option.locator('[data-se="authenticator-button"], a.button, button, a').first
    if await inner.count() and await inner.is_visible():
        await inner.click()
    else:
        await option.click()
