<div align="center">

<p><strong>⭐ If Crimson Headless Passkey is useful to you, please star it: click the ☆ Star button at the top right of the <a href="https://github.com/ventz/crimson-headless-passkey">GitHub repo page</a>.</strong></p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ventz/crimson-headless-passkey/main/images/logo-header-dark.png">
  <img src="https://raw.githubusercontent.com/ventz/crimson-headless-passkey/main/images/logo-header.png" alt="Crimson Headless Passkey" width="600">
</picture>

<p>
Headless passkey sign-in for Okta: HarvardKey by default, any Okta Identity Engine tenant by configuration.
Register a passkey once with Touch ID, then sign in from scripts, CI jobs and Playwright tests with no prompt.
</p>

<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+">
<a href="https://github.com/ventz/crimson-headless-passkey/stargazers"><img src="https://img.shields.io/github/stars/ventz/crimson-headless-passkey?style=social" alt="GitHub stars"></a>

</div>

> [!WARNING]
> This tool turns a passkey, normally locked in your device's secure hardware,
> into a **file you can copy**. Anyone who gets that file can sign in as you.
> Read [SECURITY.md](SECURITY.md) and check your organization's policy before
> using it.

## Table of Contents

- [Overview](#overview)
- [Quick Install](#quick-install)
- [Features](#features)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Overview

Okta sign-in with a passkey needs a person at the keyboard: Touch ID, a
security key, a phone. That's the point for people, and a wall for automation
that needs to reach SSO-protected pages as you: scraping your own data, testing
an internal app end to end, or a scheduled report.

Crimson Headless Passkey enrolls a second passkey on your account in a
**Chrome DevTools virtual authenticator**, keeps its key in your login Keychain,
and replays it in a Playwright browser whenever a sign-in is needed. Your
everyday passkey stays where it is, and the automation one can be revoked on
its own in Okta at any time.

## Quick Install

```bash
git clone https://github.com/ventz/crimson-headless-passkey
cd crimson-headless-passkey
uv sync
uv run playwright install chromium          # the browser; skip it to use your installed Chrome
cp .env.example .env                        # optional: settings, e.g. your username
uv run crimson-headless-passkey register    # one time, interactive
uv run crimson-headless-passkey login       # signs in with no prompt
# or: uv tool install --force .   # exposes crimson-headless-passkey and harvard-fetch
```

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/) and Google Chrome.
Tested on macOS. See [Getting Started](docs/getting-started.md) for the
registration walkthrough.

## Features

- **Prompt-free sign-in**: answers Okta's passkey challenge in a CDP virtual
  authenticator, headed or `--headless`
- **Username step handled**: fills Okta's identifier-first prompt from
  `--username`, the registered name, or Okta's remembered-username cookie
- **Session reuse**: saves cookies after each sign-in and skips the passkey
  while the Okta session is valid
- **Sign counter kept current**: persists the WebAuthn counter after every
  assertion, so Okta never sees it go backwards
- **No secrets on disk**: on macOS the private key and session live in your
  login Keychain. A file mode exists, deliberately not the default, for
  fully hands-off servers
- **Careful with secrets**: `0600` atomic writes outside the repo, SSH-style
  file and directory checks, and the authenticator is removed as soon as
  sign-in ends
- **Honest results**: success needs evidence of a sign-in, never just a
  non-IdP URL. Error pages (including `chrome-error://`
  after a late redirect) fail with a reason and are never saved, and printed
  URLs hide tokens.
- **AWS SSO consent, opt-in**: `--aws-allow` clicks Allow on the AWS IAM
  Identity Center "Allow access" page after HarvardKey and checks the approval
  page loaded. Off by default because it grants AWS access to whoever started
  the request
- **Library and CLI**: `authenticate()` and `signed_in()` return a signed-in
  Playwright context; `http_client()` exports short-lived cookies into an
  in-memory httpx session; `harvard-fetch` downloads files and folders. Exit
  codes distinguish auth failure, needs-human, network and not-found
- **Offline tests**: a fake app and IdP served by Playwright routes exercise the
  full CDP flow without touching a real tenant

## Usage

```bash
crimson-headless-passkey register                 # enroll the automation passkey
crimson-headless-passkey login [URL]              # sign in; browser stays open until ENTER
crimson-headless-passkey login --headless --close https://portal.example.edu/
crimson-headless-passkey open [URL]               # signed-in browser, left open until ENTER
crimson-headless-passkey open --no-auth [URL]     # the same page with no passkey or session
crimson-headless-passkey login -v [URL]           # -v: print every redirect hop (tokens hidden)
crimson-headless-passkey login --aws-allow URL    # also approve the AWS SSO "Allow access" page
crimson-headless-passkey status                   # what is stored, without secrets
harvard-fetch URL --out DIR                       # sign in and download a file or folder
crimson-headless-passkey fetch URL --out DIR      # same as harvard-fetch
```

Prefix with `uv run` inside the repo. Install as a tool (exposes both commands):

```bash
uv tool install --force .
harvard-fetch --help
```

Color codes and whitespace pasted into a URL are stripped. Every flag and
environment variable is in [Configuration](docs/configuration.md).

> [!IMPORTANT]
> **BREAKING in 0.3.0:** exit code `1` now means *authentication failed*
> specifically. A missing username, Okta Verify / CAPTCHA, or a chooser without
> a passkey option is `3` (needs a human). A network error is `4`. See the table
> below and the [Changelog](CHANGELOG.md).

| Code | Meaning |
|------|---------|
| 0 | OK (signed in, or every file fetched / already present) |
| 1 | Auth failed (passkey rejected, Okta error, timeout) |
| 2 | Configuration / file / browser / refused URL |
| 3 | Needs a human (no passkey option, push/number challenge, CAPTCHA, username unknown) |
| 4 | Network (chrome-error, connection refused, 5xx after retries) |
| 5 | Not found / no access after sign-in |
| 6 | Partial download (some files failed) |
| 130 | Interrupted (Ctrl-C) |

Every command finishes with one status line on stderr, for example
`crimson-headless-passkey: ok code=0 fetched=12 skipped=30 failed=0 bytes=48.1MB 9.4s`.

### Download a SharePoint / OneDrive folder

```bash
harvard-fetch 'https://harvard.sharepoint.com/sites/Example/...' --out ./data
# resumes .part files, skips files already present; PeopleSoft URLs are refused
```

**Status:** fetch is exercised offline against a fake SharePoint. It is **not**
called working against a real tenant until an approved smoke-test URL is run
(pending). Never pointed at real SharePoint from this project's automation.

### From Python

`signed_in` and `fetch` / `fetch_sync` install redaction automatically. For
other call paths (or your own httpx/Playwright code next to a signed-in
session), use:

```python
from crimson_headless_passkey import redact

with redact.active():  # preferred in library/bot code
    ...
# or redact.install() for the whole process (undo with uninstall())
```

```python
import asyncio
from pathlib import Path
from crimson_headless_passkey import Settings, signed_in, http_client, fetch_sync


async def demo():
    async with signed_in("https://portal.example.edu/") as s:
        client = await http_client(s, s.page.url)  # in-memory; nothing on disk
        r = await client.get(s.page.url)
        print(r.status_code)
        await client.aclose()


asyncio.run(demo())
report = fetch_sync("https://harvard.sharepoint.com/sites/Example/...", Path("./data"))
print(report.status_line())  # also on stderr from the CLI
raise SystemExit(
    0
    if report.ok
    else {"auth_failed": 1, "needs_human": 3, "network": 4, "not_found": 5, "partial": 6}.get(
        report.status, 2
    )
)
```

Same page, with and without the passkey:

```bash
crimson-headless-passkey open --no-auth https://login.harvard.edu/account-settings/   # sign-in form
crimson-headless-passkey open https://login.harvard.edu/account-settings/            # your account
```

Or headless: sign in with no human, then read your name and email off Okta's
account page.

```bash
uv run python examples/whoami.py --fresh
# Name:   Your Name
# Email:  you@g.harvard.edu
# Signed in with the passkey in 5.3 s. Thumbs used: 0
```

From Python:

```python
result = await authenticate(browser, Settings.from_env(), "https://portal.example.edu/")
assert result.ok
page = result.page  # signed in
```

## How It Works

```mermaid
graph LR
    A[register: Touch ID sign-in] --> B[Attach CDP virtual authenticator]
    B --> C[Okta enrolls the new passkey]
    C --> D[(Key and session in the Keychain)]
    D --> E[login: inject into a fresh browser]
    E --> F[Okta asks for a passkey]
    F --> G[Virtual authenticator signs]
    G --> H[Signed in, cookies and counter saved]
```

The ordering rules (when to attach the authenticator, why `enableUI` is off,
why credentials are captured from events) are in
[How It Works](docs/how-it-works.md).

## Documentation

| Guide | What's in it |
|-------|--------------|
| [Getting Started](docs/getting-started.md) | Registration walkthrough, first login, scripting and Python use |
| [Configuration](docs/configuration.md) | Every flag, environment variable, file and exit code; other Okta tenants |
| [How It Works](docs/how-it-works.md) | Sequence diagrams, CDP timing rules, sign counter, success detection |
| [Troubleshooting](docs/troubleshooting.md) | Known failure modes and fixes |
| [Security](SECURITY.md) | Threat model, protecting the credential, revoking it, reporting issues |
| [Changelog](CHANGELOG.md) | Release history |

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the development setup and test commands. Please report security problems
privately as described in [SECURITY.md](SECURITY.md).

This project is not affiliated with or endorsed by Harvard University or Okta.

## License

[MIT](LICENSE) © Ventz Petkov
