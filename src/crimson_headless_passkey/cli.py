"""Command-line interface: ``crimson-headless-passkey`` and ``harvard-fetch``."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from playwright.async_api import Error as PlaywrightError

from . import __version__, downloader, flows, redact, storage, userconfig
from .config import (
    ENV_HOME,
    ENV_IDP_HOSTS,
    ENV_LOGIN_URL,
    ENV_RP_ID,
    ENV_SECRET_STORE,
    ENV_SSO_HOSTS,
    ENV_UPN,
    ENV_USERNAME,
    Settings,
    validate_url,
)
from .envfile import merged_env
from .errors import LoginPasskeyError
from .exitcodes import (
    EXIT_AUTH_FAILED,
    EXIT_CONFIG,
    EXIT_INTERRUPTED,
    EXIT_OK,
    STATUS_OK,
    exit_code_for,
)
from .secretstore import KEYCHAIN, SECRET_STORES

# Back-compat names used by existing tests.
EXIT_ERROR = EXIT_CONFIG
EXIT_LOGIN_FAILED = EXIT_AUTH_FAILED


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not a number: {value!r}") from e
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from e
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
        "--config",
        type=Path,
        dest="config_file",
        help="non-secret per-user settings (default: ~/.config/crimson-headless-passkey/"
        "config.toml, or $CRIMSON_HEADLESS_PASSKEY_CONFIG)",
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
        "--upn",
        help=f"Microsoft account picker (loginfmt); default: --username (env {ENV_UPN})",
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
    common.add_argument(
        "--sso-host",
        action="append",
        dest="sso_hosts",
        type=host_arg,
        metavar="HOST",
        help=f"intermediate SSO host (e.g. login.microsoftonline.com); repeat for each "
        f"(env {ENV_SSO_HOSTS})",
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
        default=None,
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

    fetch_p = sub.add_parser(
        "fetch",
        parents=[common, browser],
        help="sign in and download a file or SharePoint/OneDrive folder",
    )
    _add_fetch_args(fetch_p)
    return parser


def _add_fetch_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("url", type=url_arg, help="file or SharePoint/OneDrive folder URL")
    p.add_argument("--out", type=Path, required=True, help="directory to write into")
    p.add_argument("--no-recurse", action="store_true", help="do not descend into subfolders")
    p.add_argument("--overwrite", action="store_true", help="re-download files already present")
    p.add_argument(
        "--dry-run", action="store_true", help="list what would be fetched, write nothing"
    )
    p.add_argument(
        "--json", action="store_true", dest="as_json", help="print a JSON report on stdout"
    )
    p.add_argument("--fresh", action="store_true", help="ignore the saved session")
    save = p.add_mutually_exclusive_group()
    save.add_argument(
        "--save-state",
        dest="save_state",
        action="store_true",
        default=False,
        help="write the session back after sign-in (off by default for fetch)",
    )
    save.add_argument(
        "--no-save-state",
        dest="save_state",
        action="store_false",
        help="do not write the session back (the default; kept for older scripts)",
    )
    p.add_argument("--headed", action="store_true", help="show the browser window")
    p.add_argument("--timeout", type=positive_float, default=None, help="sign-in timeout seconds")
    p.add_argument(
        "--concurrency", type=positive_int, default=None, help="parallel downloads (default: 4)"
    )
    p.add_argument(
        "--cookies-out",
        type=Path,
        help="EXPLICIT: write the target site's cookies to this file (0600). Off by default; "
        "anyone who can read it can act as you for that site. See SECURITY.md",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="with --cookies-out: overwrite an existing cookies file",
    )


def _standalone_fetch_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="harvard-fetch",
        description="Sign in with the HarvardKey passkey and download a file or folder.",
    )
    p.add_argument("--version", action="version", version=f"crimson-headless-passkey {__version__}")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--config", type=Path, dest="config_file")
    p.add_argument("--data-dir")
    p.add_argument("--login-url", type=url_arg)
    p.add_argument("--username")
    p.add_argument("--upn")
    p.add_argument("--secret-store", choices=SECRET_STORES)
    p.add_argument("--rp-id")
    p.add_argument("--idp-host", action="append", dest="idp_hosts", type=host_arg)
    p.add_argument("--sso-host", action="append", dest="sso_hosts", type=host_arg)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--channel")
    _add_fetch_args(p)
    return p


def settings_from(args: argparse.Namespace) -> Settings:
    config_path = getattr(args, "config_file", None)
    if config_path is not None:
        os.environ[userconfig.ENV_CONFIG] = str(config_path)
    return Settings.from_env(
        env=merged_env(args.env_file, config_file=config_path),
        data_dir=args.data_dir,
        login_url=args.login_url,
        rp_id=args.rp_id,
        idp_hosts=args.idp_hosts,
        sso_hosts=getattr(args, "sso_hosts", None),
        username=args.username,
        upn=getattr(args, "upn", None),
        secret_store=args.secret_store,
    )


def status(settings: Settings) -> int:
    print(f"data dir:     {settings.data_dir}")
    print(f"login URL:    {settings.login_url}")
    print(f"rpId:         {settings.rp_id}")
    print(f"IdP hosts:    {', '.join(settings.idp_hosts)}")
    print(f"SSO hosts:    {', '.join(settings.sso_hosts)}")
    print(f"username:     {settings.username or '(from credential or Okta cookie)'}")
    print(f"upn:          {settings.upn or '(same as username)'}")
    print(f"secret store: {settings.secret_store}")
    print(f"config:       {userconfig.default_config_path()}")

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

    session_info = storage.session_summary(settings.auth_state_file)
    if session_info:
        where, state, saved = session_info
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


def _timeout(args: argparse.Namespace) -> float:
    if getattr(args, "timeout", None) is not None:
        return args.timeout
    cfg = userconfig.load_user_config(getattr(args, "config_file", None))
    value = cfg.get("timeout", 30)
    return float(value)


def _concurrency(args: argparse.Namespace) -> int:
    if getattr(args, "concurrency", None) is not None:
        return args.concurrency
    cfg = userconfig.load_user_config(getattr(args, "config_file", None))
    return int(cfg.get("concurrency", 4))


def run_fetch(args: argparse.Namespace) -> int:
    settings = settings_from(args)
    report = asyncio.run(
        downloader.fetch(
            args.url,
            args.out,
            settings=settings,
            recursive=not args.no_recurse,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
            concurrency=_concurrency(args),
            headless=not args.headed,
            channel=args.channel,
            timeout_s=_timeout(args),
            use_saved_state=not args.fresh,
            save_state=args.save_state,
            on_status=(lambda m: print(m, file=sys.stderr)) if args.verbose else None,
            cookies_out=args.cookies_out,
            force_cookies=bool(getattr(args, "force", False)),
        )
    )
    if args.cookies_out and report.ok:
        from .config import host_of

        print(
            f"warning: wrote cookies for {host_of(report.url)} to "
            f"{args.cookies_out} (mode 0600). Anyone who can read this file can "
            "act as you for that site until the cookies expire.",
            file=sys.stderr,
        )

    if args.as_json:
        print(
            json.dumps(
                {
                    "status": report.status,
                    "url": report.url,
                    "out_dir": str(report.out_dir),
                    "fetched": report.fetched,
                    "skipped": report.skipped,
                    "failed": report.failed,
                    "bytes": report.bytes,
                    "elapsed_s": report.elapsed_s,
                    "files": [f.__dict__ for f in report.files],
                    "reason": report.reason,
                },
                indent=2,
            )
        )
    else:
        for f in report.files:
            if f.status == "fetched":
                print(report.out_dir / f.rel)
    print(report.status_line(), file=sys.stderr)
    return exit_code_for(report.status)


def run(args: argparse.Namespace) -> int:
    if args.command == "fetch":
        return run_fetch(args)
    settings = settings_from(args)
    if args.command == "status":
        code = status(settings)
        print(
            f"crimson-headless-passkey: ok code={EXIT_OK}",
            file=sys.stderr,
        )
        return code
    if args.command == "register":
        asyncio.run(
            flows.register(
                settings, force=args.force, channel=args.channel, quit_chrome=args.quit_chrome
            )
        )
        print(f"crimson-headless-passkey: ok code={EXIT_OK}", file=sys.stderr)
        return EXIT_OK
    if args.command == "open":
        url = args.url or settings.login_url
        if args.no_auth:
            asyncio.run(flows.open_url(url, channel=args.channel, verbose=args.verbose))
            print(f"crimson-headless-passkey: ok code={EXIT_OK}", file=sys.stderr)
            return EXIT_OK
        status_name = asyncio.run(
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
        # flows.login now returns a status string
        if isinstance(status_name, bool):  # pragma: no cover - old signature guard
            status_name = STATUS_OK if status_name else "auth_failed"
        code = exit_code_for(status_name)
        print(f"crimson-headless-passkey: {status_name} code={code}", file=sys.stderr)
        return code

    keep_open = args.keep_open
    if keep_open and args.headless:
        raise LoginPasskeyError("--keep-open needs a visible browser; drop --headless")
    if keep_open is None:
        keep_open = not args.headless and sys.stdin.isatty()
    status_name = asyncio.run(
        flows.login(
            settings,
            args.url or settings.login_url,
            headless=args.headless,
            channel=args.channel,
            timeout_s=_timeout(args),
            use_saved_state=not args.fresh,
            save_state=not args.no_save_state,
            keep_open=keep_open,
            verbose=args.verbose,
            aws_allow=args.aws_allow,
        )
    )
    if isinstance(status_name, bool):  # pragma: no cover
        status_name = STATUS_OK if status_name else "auth_failed"
    code = exit_code_for(status_name)
    print(f"crimson-headless-passkey: {status_name} code={code}", file=sys.stderr)
    return code


def browser_error_message(e: PlaywrightError) -> str:
    text = str(e).strip().splitlines()[0] if str(e).strip() else repr(e)
    if "Executable doesn't exist" in str(e) or "is not found at" in str(e):
        return (
            "no browser found: neither Playwright's Chromium nor Google Chrome is installed. "
            "Run `uv run playwright install chromium`, or install Google Chrome"
        )
    return f"browser error: {redact.redact_text(text)}"


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
    redact.install()
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        warn_about_protocol_logging()
        try:
            return run(args)
        except LoginPasskeyError as e:
            print(f"error: {e}", file=sys.stderr)
            print(
                f"crimson-headless-passkey: {e.status} code={e.exit_code}",
                file=sys.stderr,
            )
            return e.exit_code
        except ValueError as e:
            print(f"error: {redact.redact_text(e)}", file=sys.stderr)
            print(f"crimson-headless-passkey: config code={EXIT_CONFIG}", file=sys.stderr)
            return EXIT_CONFIG
        except PlaywrightError as e:
            print(f"error: {browser_error_message(e)}", file=sys.stderr)
            print(f"crimson-headless-passkey: config code={EXIT_CONFIG}", file=sys.stderr)
            return EXIT_CONFIG
        except OSError as e:
            print(f"error: {redact.redact_text(e)}", file=sys.stderr)
            print(f"crimson-headless-passkey: config code={EXIT_CONFIG}", file=sys.stderr)
            return EXIT_CONFIG
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            print(
                f"crimson-headless-passkey: interrupted code={EXIT_INTERRUPTED}",
                file=sys.stderr,
            )
            return EXIT_INTERRUPTED
    finally:
        redact.uninstall()


def fetch_main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``harvard-fetch`` console script."""
    redact.install()
    try:
        parser = _standalone_fetch_parser()
        args = parser.parse_args(argv)
        args.command = "fetch"
        warn_about_protocol_logging()
        try:
            return run_fetch(args)
        except LoginPasskeyError as e:
            print(f"error: {e}", file=sys.stderr)
            print(f"harvard-fetch: {e.status} code={e.exit_code}", file=sys.stderr)
            return e.exit_code
        except (ValueError, OSError) as e:
            print(f"error: {redact.redact_text(e)}", file=sys.stderr)
            print(f"harvard-fetch: config code={EXIT_CONFIG}", file=sys.stderr)
            return EXIT_CONFIG
        except PlaywrightError as e:
            print(f"error: {browser_error_message(e)}", file=sys.stderr)
            print(f"harvard-fetch: config code={EXIT_CONFIG}", file=sys.stderr)
            return EXIT_CONFIG
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return EXIT_INTERRUPTED
    finally:
        redact.uninstall()


if __name__ == "__main__":
    sys.exit(main())
