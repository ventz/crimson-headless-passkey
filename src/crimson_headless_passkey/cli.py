"""Command-line interface: ``crimson-headless-passkey {register,login,open,status}``."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from playwright.async_api import Error as PlaywrightError

from . import __version__, flows, storage
from .config import (
    ENV_HOME,
    ENV_IDP_HOSTS,
    ENV_LOGIN_URL,
    ENV_RP_ID,
    ENV_SECRET_STORE,
    ENV_USERNAME,
    Settings,
    validate_url,
)
from .envfile import merged_env
from .errors import LoginPasskeyError
from .secretstore import KEYCHAIN, SECRET_STORES

EXIT_OK, EXIT_LOGIN_FAILED, EXIT_ERROR, EXIT_INTERRUPTED = 0, 1, 2, 130


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from e
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def host_arg(value: str) -> str:
    host = value.strip().lower()
    if not host or "/" in host or ":" in host:
        raise argparse.ArgumentTypeError(f"not a bare host name: {value!r}")
    return host


def url_arg(value: str) -> str:
    try:
        return validate_url(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--env-file",
        type=Path,
        help="read CRIMSON_HEADLESS_PASSKEY_* settings from this file (default: ./.env if "
        "present); real environment variables take precedence",
    )
    common.add_argument(
        "--data-dir",
        help=f"where the credential and session live (env {ENV_HOME}; "
        "default ~/.local/share/crimson-headless-passkey)",
    )
    common.add_argument("--login-url", type=url_arg, help=f"IdP sign-in page (env {ENV_LOGIN_URL})")
    common.add_argument(
        "--username",
        help=f"answer Okta's username prompt with this (env {ENV_USERNAME}; default: "
        "the name saved at registration, then the one Okta remembered)",
    )
    common.add_argument(
        "--secret-store",
        choices=SECRET_STORES,
        help=f"where to keep the private key and saved session: the OS keychain, or files in "
        f"the data dir for fully hands-off runs (env {ENV_SECRET_STORE}; default: keychain on "
        "macOS, file elsewhere). Secrets found in the other place move on the next sign-in",
    )
    common.add_argument("--rp-id", help=f"expected WebAuthn relying-party ID (env {ENV_RP_ID})")
    common.add_argument(
        "--idp-host",
        action="append",
        dest="idp_hosts",
        type=host_arg,
        metavar="HOST",
        help=f"identity-provider host; repeat for each (env {ENV_IDP_HOSTS}, comma-separated)",
    )

    browser = argparse.ArgumentParser(add_help=False)
    browser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every page the browser goes through, redirects included (query strings hidden)",
    )
    browser.add_argument(
        "--channel",
        help="browser channel, e.g. chrome or msedge (default: Playwright's bundled Chromium)",
    )

    parser = argparse.ArgumentParser(
        prog="crimson-headless-passkey",
        description="Automated passkey (WebAuthn) sign-in for Okta via a virtual authenticator.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser(
        "register", parents=[common], help="one-time: enroll a new passkey (interactive)"
    )
    reg.add_argument("--force", action="store_true", help="replace an existing credential file")
    reg.add_argument(
        "--channel", default="chrome", help="browser channel for the real sign-in (default: chrome)"
    )
    reg.add_argument(
        "--quit-chrome",
        action="store_true",
        help="quit a running Google Chrome first (macOS)",
    )

    log = sub.add_parser("login", parents=[common, browser], help="sign in with the saved passkey")
    log.add_argument("url", nargs="?", type=url_arg, help="page to open (default: --login-url)")
    log.add_argument("--headless", action="store_true", help="run without a visible window")
    log.add_argument(
        "--timeout",
        type=positive_float,
        default=30,
        help="seconds to wait for sign-in (default: 30)",
    )
    log.add_argument(
        "--fresh", action="store_true", help="ignore the saved session; force a passkey sign-in"
    )
    log.add_argument(
        "--no-save-state", action="store_true", help="do not write the session back to disk"
    )
    keep = log.add_mutually_exclusive_group()
    keep.add_argument(
        "--keep-open",
        dest="keep_open",
        action="store_true",
        default=None,
        help="wait for ENTER before closing the browser (default when interactive and headed)",
    )
    keep.add_argument(
        "--close", dest="keep_open", action="store_false", help="close as soon as sign-in ends"
    )

    opn = sub.add_parser(
        "open",
        parents=[common, browser],
        help="open a page in a signed-in browser and leave it open (--no-auth: a plain one)",
    )
    opn.add_argument("url", nargs="?", type=url_arg, help="page to open (default: --login-url)")
    opn.add_argument(
        "--no-auth",
        action="store_true",
        help="plain browser: no passkey, no saved session (to compare with the signed-in view)",
    )
    opn.add_argument(
        "--fresh", action="store_true", help="ignore the saved session; force a passkey sign-in"
    )

    aws_help = (
        "after sign-in, click Allow on the AWS IAM Identity Center 'Allow access' consent "
        "page (e.g. from `aws sso login`) and wait for the approval page. Off by default: "
        "it grants AWS access to whatever client started the request"
    )
    log.add_argument("--aws-allow", action="store_true", help=aws_help)
    opn.add_argument("--aws-allow", action="store_true", help=aws_help)

    sub.add_parser("status", parents=[common], help="show the stored credential and session")
    return parser


def settings_from(args: argparse.Namespace) -> Settings:
    return Settings.from_env(
        env=merged_env(args.env_file),
        data_dir=args.data_dir,
        login_url=args.login_url,
        rp_id=args.rp_id,
        idp_hosts=args.idp_hosts,
        username=args.username,
        secret_store=args.secret_store,
    )


def status(settings: Settings) -> int:
    print(f"data dir:     {settings.data_dir}")
    print(f"login URL:    {settings.login_url}")
    print(f"rpId:         {settings.rp_id}")
    print(f"IdP hosts:    {', '.join(settings.idp_hosts)}")
    print(f"username:     {settings.username or '(from credential or Okta cookie)'}")
    print(f"secret store: {settings.secret_store}")

    if settings.credential_file.exists():
        creds = storage.load_credentials(settings.credential_file)
        owner_only = ", owner-only" if os.name == "posix" else ", permissions not checked"
        print(f"credential:   {settings.credential_file} ({len(creds)} passkey(s){owner_only})")
        for c in creds:
            user = f", user {c['userName']}" if c.get("userName") else ""
            where = "keychain" if c["keyStore"] == KEYCHAIN else "credential file"
            target = "keychain" if settings.secret_store == KEYCHAIN else "credential file"
            move = f" (moves to the {target} on the next sign-in)" if where != target else ""
            print(
                f"  - rpId {c['rpId']}, id {c['credentialId'][:16]}..., "
                f"signCount {c['signCount']}{user}, key in {where}{move}"
            )
    else:
        print("credential:   none (run `crimson-headless-passkey register`)")

    session = storage.session_summary(settings.auth_state_file)
    if session:
        where, state, saved = session
        in_keychain = where == "keychain"
        move = (
            " (moves on the next sign-in)"
            if in_keychain != (settings.secret_store == KEYCHAIN)
            else ""
        )
        print(
            f"session:      {'in the keychain' if in_keychain else where} "
            f"({len(state.get('cookies', []))} cookies, saved {saved}){move}"
        )
    else:
        print("session:      none")
    return EXIT_OK


def run(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    if args.command == "status":
        return status(settings)
    if args.command == "register":
        asyncio.run(
            flows.register(
                settings, force=args.force, channel=args.channel, quit_chrome=args.quit_chrome
            )
        )
        return EXIT_OK
    if args.command == "open":
        url = args.url or settings.login_url
        if args.no_auth:
            asyncio.run(flows.open_url(url, channel=args.channel, verbose=args.verbose))
            return EXIT_OK
        ok = asyncio.run(
            flows.login(
                settings,
                url,
                headless=False,
                channel=args.channel,
                use_saved_state=not args.fresh,
                keep_open=True,
                verbose=args.verbose,
                aws_allow=args.aws_allow,
            )
        )
        return EXIT_OK if ok else EXIT_LOGIN_FAILED

    keep_open = args.keep_open
    if keep_open and args.headless:
        raise LoginPasskeyError("--keep-open needs a visible browser; drop --headless")
    if keep_open is None:
        keep_open = not args.headless and sys.stdin.isatty()
    ok = asyncio.run(
        flows.login(
            settings,
            args.url or settings.login_url,
            headless=args.headless,
            channel=args.channel,
            timeout_s=args.timeout,
            use_saved_state=not args.fresh,
            save_state=not args.no_save_state,
            keep_open=keep_open,
            verbose=args.verbose,
            aws_allow=args.aws_allow,
        )
    )
    return EXIT_OK if ok else EXIT_LOGIN_FAILED


def browser_error_message(e: PlaywrightError) -> str:
    text = str(e).strip().splitlines()[0] if str(e).strip() else repr(e)
    if "Executable doesn't exist" in str(e) or "is not found at" in str(e):
        return (
            "no browser found: neither Playwright's Chromium nor Google Chrome is installed. "
            "Run `uv run playwright install chromium`, or install Google Chrome"
        )
    return f"browser error: {text}"


def warn_about_protocol_logging() -> None:
    """Playwright's protocol debug log prints every CDP message, private key included."""
    debug = os.environ.get("DEBUG", "")
    if "pw:protocol" in debug or "pw:channel" in debug or debug.strip() == "pw:*":
        print(
            "warning: DEBUG enables Playwright protocol logging, which writes the passkey's "
            "private key to the log. Unset DEBUG unless you are debugging with a throwaway "
            "credential.",
            file=sys.stderr,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    warn_about_protocol_logging()
    try:
        return run(args)
    except (LoginPasskeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except PlaywrightError as e:
        print(f"error: {browser_error_message(e)}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
