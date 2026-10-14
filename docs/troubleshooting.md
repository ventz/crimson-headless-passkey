# Troubleshooting

Start with `uv run crimson-headless-passkey status`, then rerun the failing
command headed (without `--headless`) and watch the browser.

## Table of Contents

- [Login](#login)
- [Registration](#registration)
- [Files and Permissions](#files-and-permissions)

## Login

**"Okta is asking for a username"**
The saved session has expired and no username is known. Pass
`--username you@example.edu` or set `CRIMSON_HEADLESS_PASSKEY_USERNAME`. After
one successful login, Okta's remembered-username cookie usually covers it.

**"Sign-in did not finish" while still on the Okta page**
- Okta showed a list of authenticators instead of going straight to the
  passkey. Run headed and check whether "Security Key or Biometric" is offered
  at all. If the passkey was removed from your Okta account, register again.
- The target is an Okta page this tool does not recognize as "signed in". If
  the browser clearly shows you signed in, open an issue with the URL path.

**"no saved passkey for rpId ..."**
The saved passkey belongs to a different relying party than `--rp-id` /
`CRIMSON_HEADLESS_PASSKEY_RP_ID`. `status` shows the stored rpId. Fix the
setting, or register again for this IdP.

**"the page failed to load (network error)"**
The IdP or the target site was unreachable, often on the redirect back after a
successful passkey step. The counter was still saved; just run again.

**"no browser found"**
Neither Playwright's Chromium nor Google Chrome is installed. Run
`uv run playwright install chromium`, or install Google Chrome. When only
Chrome is installed, the tool uses it and says so; that is fine.

**"Another run is using this credential; waiting for it..."**
Another sign-in with the same data directory is in progress. It continues
when that one finishes. If nothing else is running, a crashed run released its
lock when it exited, so this message clears on its own.

**It says signed in, but the target site shows a login page**
A site that never visits the IdP and stays on one URL for 3 seconds counts as
already signed in. A site that redirects to Okta from JavaScript even later
than that can look finished too early. Check it headed.

## Registration

**Touch ID never appears**
Registration needs system Chrome (`--channel chrome`, the default). Playwright's
bundled Chromium has no Touch ID or iCloud Keychain support.

**"Operation timed out or not allowed" during phase one**
The virtual authenticator was attached too early and took over the Touch ID
request. Press ENTER only when the enrollment button is on screen, never
before signing in.

**"Bluetooth is disabled" or Chrome's "Use your security key" sheet**
Chrome's own WebAuthn UI is active. The tool always uses `enableUI: false`. If
you changed it, change it back.

**"No credential was created"**
ENTER was pressed after clicking the enrollment button, so the real
authenticator handled it. Remove that new authenticator in Okta and run
`register --force`.

**Chrome refuses to start or reuses the wrong window**
Playwright starts Chrome with a throwaway profile, so it normally runs next to
your everyday Chrome. If your setup still conflicts, `register --quit-chrome`
(macOS) asks the running Chrome to quit first.

**"none of the captured passkeys is for rpId ..."**
The IdP's relying-party ID differs from `--rp-id`, so nothing was saved. Remove
the authenticator Okta just added, set `CRIMSON_HEADLESS_PASSKEY_RP_ID` to the
rpId that was printed, and run `register` again.

## Files and Permissions

**"is writable by other users ... chmod 700"**
The data directory can be written by others, who could swap the files.
Run the printed `chmod 700`.

**"is accessible by other users ... chmod 600"**
A secret file has group or world permissions (for example after a copy or a
restore). Run the printed `chmod 600` and consider rotating the passkey if the
file may have been read: see [SECURITY.md](../SECURITY.md#rotating-and-revoking).

**"The keychain is locked"**
The login Keychain opens when you log in and locks when you log out. A
scheduled sign-in needs you logged in (a locked screen is fine). On a machine
where nobody is logged in, use `--secret-store file`.

**"is not in the keychain"**
The credential file points at a Keychain item that is gone (deleted, or a
different Mac or user account). Restore the item, or remove the old passkey
in Okta and run `register --force`.

**macOS asks to allow access to the Keychain**
The program that stored the key reads it without asking. A new Python (after a
Python upgrade, for example) is a different program, so macOS asks once:
choose **Always Allow** while you are at the computer, before relying on a
scheduled run.

**Credential not found after an upgrade**
Version 0.1 kept `passkey_credential.json` and `auth_state.json` in the
current directory. Move them into the data directory (`status` prints it) and
`chmod 600` them.
