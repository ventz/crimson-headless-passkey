"""A CDP virtual FIDO2 authenticator attached to one Playwright page.

Timing matters. ``WebAuthn.enable`` routes *every* WebAuthn call on the page
to virtual authenticators, so it also blocks Touch ID and security keys.
Registration therefore attaches only right before the enrollment step, and
login attaches before the first navigation so the credential is present when
the IdP calls ``navigator.credentials.get()``.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from typing import Any

from playwright.async_api import BrowserContext, CDPSession, Page
from playwright.async_api import Error as PlaywrightError

# A platform-style (``internal``) CTAP 2.1 authenticator that holds discoverable
# credentials and reports user verification as done, with no human involved.
AUTHENTICATOR_OPTIONS = {
    "protocol": "ctap2",
    "ctap2Version": "ctap2_1",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,
    "automaticPresenceSimulation": True,
}


class VirtualAuthenticator:
    def __init__(self, session: CDPSession) -> None:
        self.session = session
        self.authenticator_id: str | None = None
        # Credentials created on this authenticator, captured from events. The
        # event is the reliable source: an IdP usually navigates right after
        # enrollment, and polling getCredentials afterwards can fail.
        self.added: list[dict[str, Any]] = []
        # Latest signCount per credentialId, from assertion events.
        self.sign_counts: dict[str, int] = {}

    @classmethod
    async def attach(cls, context: BrowserContext, page: Page) -> VirtualAuthenticator:
        session = await context.new_cdp_session(page)
        authn = cls(session)
        session.on("WebAuthn.credentialAdded", authn._on_added)
        session.on("WebAuthn.credentialAsserted", authn._on_asserted)
        # enableUI=False keeps Chrome's own "use your security key" sheet out of
        # the way; with True it covers the page and the virtual authenticator
        # never gets the request.
        await session.send("WebAuthn.enable", {"enableUI": False})
        result = await session.send(
            "WebAuthn.addVirtualAuthenticator", {"options": AUTHENTICATOR_OPTIONS}
        )
        authn.authenticator_id = result["authenticatorId"]
        return authn

    async def add_credential(self, cred: Mapping[str, Any]) -> None:
        """Inject a saved credential.

        It is always added as discoverable (resident) so the IdP can find it
        without first being told a username.
        """
        credential = {
            "credentialId": cred["credentialId"],
            "rpId": cred["rpId"],
            "privateKey": cred["privateKey"],
            "signCount": cred["signCount"],
            "isResidentCredential": True,
        }
        # Re-assert what the authenticator reported at enrollment: WebAuthn lets
        # a relying party reject a credential whose backup-eligible flag changes.
        for key in ("userHandle", "backupEligibility", "backupState"):
            if key in cred:
                credential[key] = cred[key]
        await self.session.send(
            "WebAuthn.addCredential",
            {"authenticatorId": self.authenticator_id, "credential": credential},
        )

    async def get_credentials(self) -> list[dict[str, Any]]:
        result = await self.session.send(
            "WebAuthn.getCredentials", {"authenticatorId": self.authenticator_id}
        )
        return result.get("credentials", [])

    async def current_sign_counts(self) -> dict[str, int]:
        """Sign counts from events, topped up from getCredentials when the session is alive."""
        counts = dict(self.sign_counts)
        try:
            for cred in await self.get_credentials():
                cid = cred["credentialId"]
                counts[cid] = max(counts.get(cid, 0), cred["signCount"])
        except PlaywrightError:
            pass  # session gone (e.g. page closed); events are all we have
        return counts

    async def detach(self) -> None:
        """Remove the authenticator and stop intercepting WebAuthn on the page.

        While attached, any page on the relying party's origin in this tab gets
        silent, user-verified assertions (including Okta's step-up prompts), so
        it stays attached only for the sign-in itself. Errors are ignored: the
        page may already be gone.
        """
        with contextlib.suppress(PlaywrightError):
            if self.authenticator_id is not None:
                await self.session.send(
                    "WebAuthn.removeVirtualAuthenticator",
                    {"authenticatorId": self.authenticator_id},
                )
            await self.session.send("WebAuthn.disable")
        with contextlib.suppress(PlaywrightError):
            await self.session.detach()
        self.authenticator_id = None
        self.added.clear()  # drop in-memory copies of private keys

    def _on_added(self, params: Mapping[str, Any]) -> None:
        self.added.append(dict(params.get("credential", params)))

    def _on_asserted(self, params: Mapping[str, Any]) -> None:
        cred = params.get("credential", params)
        cid, count = cred.get("credentialId"), cred.get("signCount")
        if cid is not None and count is not None:
            self.sign_counts[cid] = max(self.sign_counts.get(cid, 0), count)
