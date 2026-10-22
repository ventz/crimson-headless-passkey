# Getting Started

This walks through a first registration and login, then shows how to use the
tool from scripts and Python.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Register a Passkey](#register-a-passkey)
- [Log In](#log-in)
- [Use It From Scripts](#use-it-from-scripts)
- [Use It From Python](#use-it-from-python)

## Prerequisites

- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- Google Chrome installed (registration uses it for Touch ID)
- An Okta account where you may add a "Security Key or Biometric"
  authenticator, and an existing way to sign in (Touch ID passkey, security
  key, or Okta Verify)
- Tested on macOS only. Nothing in `login` is macOS-specific, but Linux and
  Windows are untested.

## Install

```bash
git clone https://github.com/ventz/crimson-headless-passkey
cd crimson-headless-passkey
uv sync
uv run playwright install chromium   # recommended; without it the tool uses installed Chrome
cp .env.example .env                 # optional: settings; see Configuration
```

Put your Okta username in `.env` (`CRIMSON_HEADLESS_PASSKEY_USERNAME=...`) and
`login` can answer Okta's username prompt even after the saved session has
expired.

## Register a Passkey

```bash
uv run crimson-headless-passkey register
```

1. Chrome opens on the sign-in page. Sign in the normal way (username, then
   Touch ID, Duo or your security key).
2. On your account page, under **Security methods**, click **Manage security
   methods**. For HarvardKey that is
   `https://login.harvard.edu/account-settings/security`.
3. Find **Security Key or Biometric Authenticator** and click **+ Set up
   another** (**Set up** if you have none yet). Not Okta Verify or FastPass:
   FastPass isn't WebAuthn. Verify again if Okta asks.
4. When the enrollment screen with its button is showing, **don't click it
   yet: switch to the terminal and press ENTER first**. That attaches the
   virtual authenticator.
5. Click the enrollment button in Chrome. No Touch ID or passkey prompt
   appears: the virtual authenticator answers. If one does, cancel it; the
   authenticator wasn't attached.
6. When Okta confirms, press ENTER again. On macOS the private key and the
   session are saved in your login Keychain, and only non-secret
   fields go to `~/.local/share/crimson-headless-passkey/`. Elsewhere (or with
   `--secret-store file`) they are saved as `0600` files there instead.

Check the result:

```bash
uv run crimson-headless-passkey status
```

Okta now lists one more authenticator on your account. Give it a recognizable
name if your Okta allows renaming, so you can revoke it later.

## Log In

```bash
uv run crimson-headless-passkey login                                   # Okta itself
uv run crimson-headless-passkey login https://portal.example.edu/page   # any SSO-protected page
```

A browser window opens, signs in without any prompt, and stays open until you
press ENTER. The first login after the session expires needs your username
(see [Configuration](configuration.md#settings)); later ones pick it up from
Okta's remembered-username cookie.

## Use It From Scripts

```bash
uv run crimson-headless-passkey login --headless --close https://portal.example.edu/
echo $?   # 0 signed in, 1 not signed in, 2 configuration error
```

The refreshed cookies are saved in the Keychain (or `auth_state.json` with
`--secret-store file`). Any Playwright script can reuse them: load them with
`storage.load_auth_state(settings.auth_state_file, settings.secret_store)` and
pass the result to `browser.new_context(storage_state=...)`.

## Use It From Python

`authenticate()` returns a signed-in Playwright context and page and leaves the
browser to you:

```python
import asyncio

from playwright.async_api import async_playwright

from crimson_headless_passkey import Settings, authenticate


async def main():
    settings = Settings.from_env()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        result = await authenticate(browser, settings, "https://portal.example.edu/")
        if not result.ok:
            raise SystemExit(f"not signed in: {result.page.url}")
        print(await result.page.title())
        await browser.close()


asyncio.run(main())
```

[`examples/whoami.py`](../examples/whoami.py) is a complete example: it signs
in to `https://login.harvard.edu/account-settings/` and prints the name and
email Okta shows there.

Pass `context=` to use a context you created yourself (with a proxy or routes,
for example). `authenticate()` keeps the credential's sign counter current on
disk and removes the virtual authenticator before returning; saving the session
is up to you. When `result.ok` is false, `result.reason` says why.

Never turn on Playwright tracing or `DEBUG=pw:protocol` around
`authenticate()`, and never pass it a browser attached over a remote-debugging
port: all three expose the private key.
