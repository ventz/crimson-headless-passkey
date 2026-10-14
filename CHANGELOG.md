# Changelog

## 0.2.0 - Unreleased

Renamed from `login-passkey` and restructured for a public release.

### Added

- `--aws-allow` (`login`, `open`): after sign-in, click Allow on the AWS IAM
  Identity Center "Allow access" consent page and confirm the approval page
  loaded. Off by default, since it grants AWS access to whichever client
  started the request.

- Single `crimson-headless-passkey` command with `register`, `login`, `open`
  and `status` subcommands (replaces `register_passkey.py`, `login.py`,
  `goto.py`), plus `python -m crimson_headless_passkey`.
- Library entry point `authenticate()` returning a signed-in Playwright
  context and page.
- Okta identifier-first username prompt is answered automatically
  (`--username`, env var, registered name, or Okta's `ln` cookie).
- Signed-in detection for Okta's own pages, so `login` against the IdP itself
  succeeds.
- WebAuthn sign counter is persisted after every assertion, forward-only.
- Secrets are kept in the OS keychain (`--secret-store keychain`, the default
  on macOS): the private key and the saved session, so nothing secret is
  stored on disk. `--secret-store file` keeps both in `0600` files for fully
  hands-off runs where nobody is logged in. Switching moves existing secrets
  on the next sign-in, and `status` shows where each one lives.
- `examples/whoami.py`: signs in to HarvardKey's account page with no human and
  prints the name and email shown there.
- Settings for other Okta tenants: `--login-url`, `--rp-id`, `--idp-host`,
  `--data-dir`, and matching `CRIMSON_HEADLESS_PASSKEY_*` env vars.
- `login` flags: `--headless`, `--channel`, `--timeout`, `--fresh`,
  `--no-save-state`, `--keep-open` / `--close`; exit codes 0/1/2/130.
- `.env` support: `./.env` or `--env-file`, limited to
  `CRIMSON_HEADLESS_PASSKEY_*` keys, refused when others can write to it, and
  below real environment variables. Ships with `.env.example`.
- `register` refuses to overwrite an existing credential without `--force`.
- Offline end-to-end tests against a fake IdP; unit tests for storage and
  configuration.
- Security hardening from four independent reviews:
  - Success needs an https destination plus evidence of sign-in, and browser
    error pages fail with a reason (`LoginResult.reason`).
  - The virtual authenticator is removed after sign-in.
  - A run lock prevents concurrent counter reuse.
  - SSH-style directory checks, plus no-follow, descriptor-checked reads.
  - Stricter credential validation.
  - Passkeys are filtered by rpId on login and registration.
  - Printed URLs are redacted.
  - A warning appears when Playwright protocol logging is on.
  - The release package is built from an explicit file list.
- Ctrl-C at a prompt exits immediately (exit 130), and browser errors print one
  line (exit 2) with an install hint.
- `SECURITY.md` with the threat model, the revocation runbook and admin
  guidance.

### Fixed

- A sign-in whose final page was Chrome's error page
  (`chrome-error://chromewebdata/`) was reported as "Signed in" and saved when
  a script redirect failed after sign-in. Any non-http(s) final URL is now a
  failure (exit `1`, with a reason) and the session is not saved.
- URL arguments are stripped of terminal color codes, control characters and
  whitespace before use.

- A sign-in that started on one of Okta's own signed-in pages (for example
  `/account-settings/`) could be reported as finished before Okta redirected to
  its sign-in form. Only an IdP page that is not itself a destination now
  counts as evidence that a sign-in happened.

### Changed

- `open URL` now opens the page in a signed-in browser; `open --no-auth URL`
  is the plain browser it used to be, so the two show the same page with and
  without the passkey.
- With no `--channel`, a missing Playwright Chromium falls back to an
  installed Google Chrome instead of failing.
- `-v` / `--verbose` on `login` and `open` prints every page the browser goes
  through, redirects included, with timings and query strings hidden.
  `authenticate()` takes `on_navigation=` for the same in library code.
- Redirects are followed before anything is reported: after a sign-in
  (`authenticate()`, so `login`, `open` and library callers) and in
  `open --no-auth`, the tool waits up to 5 s for script redirects to finish.

- http URLs are refused except on loopback. The Playwright floor is now 1.58.
- Secrets moved from the working directory to
  `~/.local/share/crimson-headless-passkey/`, written `0600` atomically, and
  refused when readable by other users.
- IdP hosts are matched by parsed hostname, not substring.
- `register` no longer quits a running Chrome; use `--quit-chrome` if needed.
- The session file is only rewritten after a successful sign-in.

## 0.1.0 - 2026-03-05

- First working version: `register_passkey.py`, `login.py`, `goto.py`.
