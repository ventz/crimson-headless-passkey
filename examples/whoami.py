"""Sign in to HarvardKey with no human, then read your name and email off the page.

The page is Okta's own account settings (https://login.harvard.edu/account-settings/),
so the demo touches nothing but your own HarvardKey account.

    uv run python examples/whoami.py                      # reuse the saved session if valid
    uv run python examples/whoami.py --fresh              # force a passkey sign-in
    uv run python examples/whoami.py --headed --fresh     # watch it happen

Settings come from ./.env and CRIMSON_HEADLESS_PASSKEY_* variables, like the CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time

from playwright.async_api import async_playwright

from crimson_headless_passkey import Settings, authenticate, storage
from crimson_headless_passkey.envfile import merged_env

ACCOUNT_SETTINGS = "https://login.harvard.edu/account-settings/"
# Okta marks the page header with data-se attributes (seen 2026-10-03).
NAME = '[data-se="header-fullName"]'
EMAIL = '[data-se="header-email"]'


async def whoami(*, fresh: bool, headed: bool) -> int:
    settings = Settings.from_env(env=merged_env(None))
    before = storage.load_credentials(settings.credential_file)[0]["signCount"]
    started = time.monotonic()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not headed, channel="chrome")
        try:
            result = await authenticate(
                browser, settings, ACCOUNT_SETTINGS, use_saved_state=not fresh
            )
            if not result.ok:
                print(f"Not signed in: {result.reason}", file=sys.stderr)
                return 1
            page = result.page
            name = (await page.locator(NAME).inner_text(timeout=15_000)).strip()
            email = (await page.locator(EMAIL).inner_text(timeout=15_000)).strip()
            storage.save_auth_state(
                settings.auth_state_file,
                await result.context.storage_state(),
                settings.secret_store,
            )
        finally:
            await browser.close()

    after = storage.load_credentials(settings.credential_file)[0]["signCount"]
    used = "passkey" if after > before else "saved session"
    print(f"Name:   {name}")
    print(f"Email:  {email}")
    print(f"Signed in with the {used} in {time.monotonic() - started:.1f} s. Thumbs used: 0")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fresh", action="store_true", help="ignore the saved session")
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    args = parser.parse_args()
    return asyncio.run(whoami(fresh=args.fresh, headed=args.headed))


if __name__ == "__main__":
    sys.exit(main())
