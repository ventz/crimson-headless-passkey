# Configuration

Every setting has a command-line flag and an environment variable, and the
environment variables can live in a `.env` file. Precedence, highest first:
flags, real environment variables, `.env`, built-in defaults.

## Table of Contents

- [Settings](#settings)
- [The .env File](#the-env-file)
- [Data Files](#data-files)
- [Commands and Flags](#commands-and-flags)
- [Exit Codes](#exit-codes)
- [Using Another Okta Tenant](#using-another-okta-tenant)

## Settings

| Flag | Environment variable | Default | Meaning |
|------|----------------------|---------|---------|
| `--data-dir` | `CRIMSON_HEADLESS_PASSKEY_HOME` | `$XDG_DATA_HOME/crimson-headless-passkey`, else `~/.local/share/crimson-headless-passkey` | Where the data files live |
| `--login-url` | `CRIMSON_HEADLESS_PASSKEY_URL` | `https://login.harvard.edu` | Okta sign-in page; the default URL for `login`, `open` and `register` |
| `--rp-id` | `CRIMSON_HEADLESS_PASSKEY_RP_ID` | `login.harvard.edu` | WebAuthn relying-party ID. `register` only saves passkeys for it, and `login` only injects passkeys for it. |
| `--idp-host` (repeatable) | `CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS` (comma-separated) | `login.harvard.edu,harvard.okta.com` | Hosts that count as "still signing in" |
| `--username` | `CRIMSON_HEADLESS_PASSKEY_USERNAME` | name saved at registration, then Okta's `ln` cookie | Answer for Okta's username prompt |
| `--secret-store` | `CRIMSON_HEADLESS_PASSKEY_SECRET_STORE` | `keychain` on macOS, `file` elsewhere | Where the private key and saved session are kept: the OS keychain, or `0600` files for fully hands-off runs where nobody is logged in. **`file` puts secrets on disk on purpose; read [SECURITY.md](../SECURITY.md#where-the-secrets-live) first.** Secrets found in the other place move on the next sign-in. |
| `--upn` | `CRIMSON_HEADLESS_PASSKEY_UPN` | same as `--username` | What to type into Microsoft's "Pick an account" (loginfmt) on the way to SharePoint / OneDrive |
| `--sso-host` (repeatable) | `CRIMSON_HEADLESS_PASSKEY_SSO_HOSTS` | `login.microsoftonline.com,login.microsoft.com,login.windows.net` | Intermediate SSO hosts that count as "still signing in", never as a destination |
| `--config` | `CRIMSON_HEADLESS_PASSKEY_CONFIG` | `~/.config/crimson-headless-passkey/config.toml` | Non-secret per-user settings file |

## The .env File

```bash
cp .env.example .env    # then edit; it is already in .gitignore
```

The tool reads `./.env` from the directory you run it in, or the file named by
`--env-file PATH` (which must exist). Format: `KEY=value` lines, `#` comments,
an optional `export` prefix, and single- or double-quoted values. There is no
variable expansion.

- Only `CRIMSON_HEADLESS_PASSKEY_*` keys are read. Other keys are ignored, so
  a `.env` shared with other tools is fine, and nothing else is put into the
  environment.
- The file must be owned by you and not writable by anyone else, otherwise the
  tool refuses it (`chmod go-w .env`). It controls which hosts receive your
  username and where the private key is read from, so a `.env` planted by
  someone else must not count.
- Library callers opt in with
  `Settings.from_env(env=merged_env(Path(".env")))`.

## Data Files

The data files are written `0600` through a temp file and an atomic
rename. The tool applies SSH's rules on every load and save: it refuses
a file that other users can read, that someone else owns, that is a symlink or
not a regular file, and a directory that someone else owns or can write to.
New data directories are created `0700`. A relative `--data-dir` is resolved
against the current directory once, at startup.

URLs must be https. Plain http is accepted only for `localhost`, `127.0.0.1`
and `::1`, for local testing.

| File | Contents | Sensitivity |
|------|----------|-------------|
| `passkey_credential.json` | JSON list of credentials: `credentialId`, `rpId`, `signCount`, `userHandle`, `isResidentCredential`, `keyStore`, and `userName` / `userDisplayName` / `backupEligibility` / `backupState` when known. With `keyStore: "file"` it also holds `privateKey` (PKCS#8 P-256, base64). | With the key in the keychain: not secret on its own. With `keyStore: "file"`: **equivalent to your passkey**; anyone with it can sign in as you. |
| Keychain item, account `<rpId>/<credentialId>` (keychain store only) | The private key. All items use the service name `crimson-headless-passkey`. | **Equivalent to your passkey.** |
| `auth_state.json` (file store only) | Playwright storage state: cookies and local storage for the IdP and every site visited | Live session tokens until they expire |
| Keychain item, account `session:<data dir>` (keychain store only) | The same storage state, plus when it was saved | Live session tokens until they expire |
| `.lock` | Empty; held during a sign-in so concurrent runs take turns | None |

`crimson-headless-passkey status` shows what is stored without printing any
secret.

## Commands and Flags

| Command | Flags | Notes |
|---------|-------|-------|
| `register` | `--force`, `--channel` (default `chrome`), `--quit-chrome` | Interactive. Refuses to overwrite an existing credential without `--force`. |
| `login [URL]` | `--headless`, `--channel`, `--timeout` (seconds, default 30), `--fresh`, `--no-save-state`, `--keep-open` / `--close`, `-v` / `--verbose`, `--aws-allow` | `--fresh` ignores saved cookies, so it needs `--username`. The browser stays open for inspection only when headed and run from a terminal; `--keep-open` cannot be combined with `--headless`. The session file is only rewritten after a successful sign-in. |
| `open [URL]` | `--no-auth`, `--fresh`, `--channel`, `-v` / `--verbose`, `--aws-allow` | Opens the page in a signed-in browser and leaves it open until ENTER. With `--no-auth`: a plain browser with no passkey and no cookies, so the same URL shows what an unauthenticated visit looks like. |
| `status` | | Settings in effect plus a summary of the stored files |
| `fetch URL` (also `harvard-fetch`) | `--out`, `--no-recurse`, `--overwrite`, `--dry-run`, `--json`, `--concurrency`, `--cookies-out`, `--headed`, `--fresh`, `--no-save-state`, `--timeout` | Sign in and download a file or SharePoint/OneDrive folder |

All commands accept the settings flags from the table above.

`-v` / `--verbose` prints every page the browser goes through, redirects
included, with the time since start. Query strings and fragments are hidden,
since they can carry OAuth codes and tokens:

```text
  ->  0.45s  https://login.harvard.edu/account-settings/
  ->  1.98s  https://login.harvard.edu/account-settings/home
  ->  2.36s  https://login.harvard.edu/oauth2/v1/authorize (query/fragment hidden)
  ->  6.74s  https://login.harvard.edu/account-settings/callback (query/fragment hidden)
  ->  7.35s  https://login.harvard.edu/account-settings/home
```

URL arguments (`login`, `open`, `--login-url`) are cleaned before use:
terminal color codes and other escape sequences, control characters and all
whitespace are removed, so a URL copied from colored output (`aws sso login`)
or wrapped across lines when pasted still works. The result must still be
https (http only on loopback).

`--aws-allow` handles the AWS IAM Identity Center consent page that follows
the HarvardKey step for `aws sso login`. After sign-in, if the page is on an
AWS access portal (`*.awsapps.com` or `*.app.aws`) and shows **Allow access**,
the tool clicks it and waits for the "Request approved" page. A click that
ends on an error page, or no approval page within `--timeout`, exits `1` and
leaves the saved session unchanged. If no consent page appears (AWS skips it
for a client approved before), it says so and carries on. It is **off by
default**: Allow hands AWS credentials to whichever client started the
request, and a phished device code looks exactly like your own `aws sso
login`. Pass it only for a request you started yourself.

`--channel` picks the browser: omit it for Playwright's bundled Chromium
(install with `uv run playwright install chromium`; when it is missing, the
tool falls back to an installed Google Chrome and says so), or use `chrome` /
`msedge` for an installed browser.

## Exit Codes

**BREAKING in 0.3.0:** code `1` used to mean every "not signed in". It now means
authentication failed specifically. See [CHANGELOG](../CHANGELOG.md) for the
old-to-new mapping.

| Code | Meaning |
|------|---------|
| 0 | OK (signed in, or every file fetched / already present) |
| 1 | Auth failed (passkey rejected, Okta error banner, timeout) |
| 2 | Configuration, file, browser or refused-URL error |
| 3 | Needs a human (no passkey option, Okta Verify / push / code, CAPTCHA, username unknown) |
| 4 | Network (chrome-error, connection refused, 5xx after retries) |
| 5 | Not found / no access after sign-in |
| 6 | Partial download (some files failed) |
| 130 | Interrupted with Ctrl-C |

Every command prints one status line on stderr:
`crimson-headless-passkey: <status> code=<n> ...`.

## Per-user Config File

`~/.config/crimson-headless-passkey/config.toml` (or `--config` /
`CRIMSON_HEADLESS_PASSKEY_CONFIG`) holds non-secret defaults:

```toml
username = "you@example.edu"
upn = "you@harvard.edu"          # Microsoft account picker; default = username
timeout = 30
concurrency = 4
```

Secret-looking keys (`password`, `token`, …) and token-shaped values are
refused. Precedence: flags > environment > `.env` > this file > built-ins.

## `fetch` / `harvard-fetch`

| Flag | Meaning |
|------|---------|
| `--out DIR` | Directory to write into (required) |
| `--no-recurse` | Do not descend into subfolders |
| `--overwrite` | Re-download files already present |
| `--dry-run` | List what would be fetched; write nothing |
| `--json` | Print a JSON report on stdout |
| `--concurrency N` | Parallel downloads (default 4) |
| `--cookies-out FILE` | Explicit: write the site's cookies (0600). Off by default |
| `--headed` | Show the browser |
| `--fresh` / `--no-save-state` | Same meaning as `login` |

PeopleSoft URLs are refused. SharePoint / OneDrive folders resume via `.part`
files and skip unchanged files using `DIR/.harvard-fetch.json` (non-secret).

## Using Another Okta Tenant

Nothing in the code is Harvard-specific beyond the defaults. For another Okta
org, set the three host settings, then register:

```bash
export CRIMSON_HEADLESS_PASSKEY_URL=https://example.okta.com
export CRIMSON_HEADLESS_PASSKEY_RP_ID=example.okta.com
export CRIMSON_HEADLESS_PASSKEY_IDP_HOSTS=example.okta.com
uv run crimson-headless-passkey register
```

The relying-party ID is normally the Okta host (or its custom domain).
`register` prints the rpId it actually captured, so a wrong guess shows up
immediately. Only Okta Identity Engine's identifier-first sign-in has been
tested; other IdPs may need a different username selector in `flows.py`.
