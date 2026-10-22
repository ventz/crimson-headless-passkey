# Changelog

## 0.4.0 - Unreleased

### Changed

- **`fetch` / `harvard-fetch` no longer save the session by default.** A
  download job now reads the saved session (unless `--fresh`) but writes it
  back only with the new `--save-state` flag. `--no-save-state` is still
  accepted and matches the new default. The library `fetch()` /
  `fetch_sync()` default is now `save_state=False`. `login` is unchanged and
  still saves the session.

### Fixed

- The stderr status line printed `code=[REDACTED]` instead of the exit code,
  because secret redaction treated it as an OAuth `code=` value. A bare 1-3
  digit `code=N` is now left alone; real OAuth codes are still scrubbed.

## 0.3.0 - Unreleased

**BREAKING:** exit code 1 no longer means every "login did not finish". It now
means authentication failed specifically. Other former-1 cases move to new
codes (see the mapping below and [docs/configuration.md](docs/configuration.md)).

### Added

- `harvard-fetch URL --out DIR` (and `crimson-headless-passkey fetch`): sign in
  and download one file or a SharePoint/OneDrive folder recursively. Resumable
  (`.part` + HTTP Range), skips files already present (non-secret
  `.harvard-fetch.json` manifest), refuses PeopleSoft URLs.
- Library helpers: `signed_in()` (async context manager), `http_client()`
  (in-memory httpx session for one site), `fetch` / `fetch_sync`.
- `--cookies-out FILE`: explicit opt-in to write one site's cookies with mode
  0600. Off by default; documented in SECURITY.md.
- Per-user config file `~/.config/crimson-headless-passkey/config.toml`
  (override with `CRIMSON_HEADLESS_PASSKEY_CONFIG` / `--config`). Non-secret
  settings only; secret-looking keys and values are refused.
- `--upn` / `CRIMSON_HEADLESS_PASSKEY_UPN` for Microsoft's account picker
  (default: the HarvardKey username). "Stay signed in?" is answered **No**.
- Okta authenticator chooser and error-banner handling; Microsoft Entra
  `loginfmt` / KMSI pages treated as intermediate SSO hosts (never destinations).
- `redact.py`: registry of known secrets plus shape-based scrubbing. Wired into
  exceptions, `sys.excepthook`, logging and stderr. Covered by a mutation-checked
  test.
- `pathsafe.py`: hostile SharePoint names cannot escape `--out` (`.part`
  included). Mutation-style cases: `..`, absolute paths, Windows separators,
  NUL/controls, reserved names, symlinks.
- Distinct exit codes: 0 ok, 1 auth failed, 2 config, 3 needs human, 4 network,
  5 not found, 6 partial, 130 interrupted. Every command ends with one status
  line on stderr.
- Dependency: `httpx` (streaming downloads).

### Exit code mapping (BREAKING)

| Before (0.2) | After (0.3) | Meaning |
|---|---|---|
| 0 | 0 | OK |
| 1 (timeout / passkey rejected / Okta error) | 1 | Auth failed |
| 1 (username unknown / Okta Verify / CAPTCHA / chooser without passkey) | 3 | Needs a human |
| 1 (chrome-error / connection refused) | 4 | Network |
| (new) | 5 | Not found / no access after sign-in |
| (new) | 6 | Partial download (some files failed) |
| 2 | 2 | Config / file / browser / refused URL |
| 130 | 130 | Interrupted |

### Security (review 2026-10-20 PASS-with-fixes)

- Manual https redirect guard before each hop; Secure/host-only cookies; IdP block list
  is builtins∪config; `redact.install` / `active` for bots; library logger filters at
  import; `--cookies-out` reuses the fetch session and refuses overwrite without
  `--force`; `--out` must not be group/world-writable.

### Notes

- Fetch was verified against a real SharePoint site (files and folders,
  including sharing links). Offline tests cover the mechanism.
- Session saving stays on by default (Keychain on macOS). Changed for fetch in 0.4.0.


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
