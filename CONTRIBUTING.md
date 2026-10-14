# Contributing

## Development Setup

```bash
git clone https://github.com/ventz/crimson-headless-passkey
cd crimson-headless-passkey
uv sync
uv run playwright install chromium   # or rely on an installed Chrome
cp .env.example .env                 # optional; never commit .env
```

## Checks

```bash
uv run pytest            # unit tests plus the offline browser tests
uv run ruff check .
uv run ruff format --check .
```

The browser tests (`tests/test_browser.py`) need Playwright's Chromium or an
installed Chrome and skip themselves when neither is present. They serve a fake
app and a fake IdP through Playwright routes, so they never contact a real
identity provider. Please keep it that way: never add tests that sign in to a
real tenant, and never commit a real `passkey_credential.json` or
`auth_state.json`, even an expired one.

## Pull Requests

- Keep changes focused and add a test for any behavior change.
- If you change CDP timing, the authenticator options or the sign-in detection,
  update [docs/how-it-works.md](docs/how-it-works.md) in the same PR.
- Use American English spelling in code, docs and messages.
- Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".
