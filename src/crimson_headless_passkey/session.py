"""One-call helpers that hand a signed-in Playwright context (or cookies) to a script.

``signed_in`` launches Chromium, runs ``authenticate``, detaches the virtual
authenticator and yields a ``SignedIn`` with the browser, context and page.
The caller never sees the private key: it lives only while ``authenticate``
runs, under the data-dir lock.

``http_client`` exports short-lived cookies for one site into an in-memory
``httpx.AsyncClient``. Nothing goes to disk. Writing cookies needs the
explicit ``--cookies-out`` flag (or ``save_cookies``), which uses the same
0600 atomic write as the rest of the tool; see SECURITY.md.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookiejar import Cookie, DefaultCookiePolicy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from . import flows, redact, storage
from .config import (
    DEFAULT_IDP_HOSTS,
    DEFAULT_SSO_HOSTS,
    Settings,
    host_of,
    is_peoplesoft_url,
    validate_url,
)
from .errors import AuthFailedError, ConfigError, NetworkError, RefusedURLError, error_for_status

MAX_REDIRECTS = 10

# Exact IdP/SSO hosts: forbidden as request/redirect targets AND excluded from
# cookie jars. Configured idp_hosts / sso_hosts ADD to this set; they never
# replace it.
BUILTIN_BLOCKED_HOSTS = (
    *DEFAULT_IDP_HOSTS,
    *DEFAULT_SSO_HOSTS,
    "login.live.com",
)
# Parent-domain suffixes used ONLY when filtering cookies out of the jar
# (e.g. Domain=.harvard.edu must never ride along). Request/redirect URL
# checks do NOT use these — otherwise canvas.harvard.edu would be refused.
COOKIE_BLOCKED_SUFFIXES = (
    ".okta.com",
    ".harvard.edu",
)
# Back-compat alias for tests/docs that still name the constant.
BUILTIN_BLOCKED_SUFFIXES = COOKIE_BLOCKED_SUFFIXES


@dataclass
class SignedIn:
    """A signed-in browser the caller owns for the duration of ``signed_in``."""

    browser: Browser
    context: BrowserContext
    page: Page
    settings: Settings
    url: str

    async def cookies_for(self, site: str, *, include_idp: bool = False) -> list[dict[str, Any]]:
        return await cookies_for_site(self.context, site, self.settings, include_idp=include_idp)


@contextlib.asynccontextmanager
async def signed_in(
    url: str | None = None,
    settings: Settings | None = None,
    *,
    headless: bool = True,
    channel: str | None = None,
    timeout_s: float = 30,
    use_saved_state: bool = True,
    save_state: bool = True,
) -> AsyncIterator[SignedIn]:
    """Sign in and yield a ``SignedIn``. The browser closes when the block exits.

    Raises ``AuthFailedError``, ``NeedsHumanError``, ``NetworkError`` or
    ``NotFoundError`` (each carries ``.exit_code``) when sign-in does not
    finish. Raises ``RefusedURLError`` for PeopleSoft URLs (fetch and
    helpers; the CLI ``login`` command is the only allowed path, with
    ``--no-save-state``).
    """
    with redact.active():
        settings = settings or Settings.from_env()
        url = validate_url(url or settings.login_url)
        if is_peoplesoft_url(url):
            raise RefusedURLError(
                "PeopleSoft is refused by the library helpers. Use the CLI only: "
                "`crimson-headless-passkey login -v --headless --close --no-save-state URL`"
            )
        async with async_playwright() as p:
            browser = await flows.launch(p, headless=headless, channel=channel)
            try:
                result = await flows.authenticate(
                    browser,
                    settings,
                    url,
                    timeout_s=timeout_s,
                    use_saved_state=use_saved_state,
                )
                if not result.ok:
                    await result.context.close()
                    raise error_for_status(result.status, result.reason)
                if save_state:
                    state = await result.context.storage_state()
                    redact.register_storage_state(state)
                    storage.save_auth_state(settings.auth_state_file, state, settings.secret_store)
                yield SignedIn(
                    browser=browser,
                    context=result.context,
                    page=result.page,
                    settings=settings,
                    url=result.page.url,
                )
            finally:
                await flows.close_quietly(browser)


def cookie_matches_host(cookie_domain: str, host: str) -> bool:
    """RFC 6265-ish: the cookie's Domain attribute covers ``host``."""
    domain = cookie_domain.lstrip(".").lower()
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def is_proper_subdomain(host: str, parent: str) -> bool:
    """True when ``host`` is ``parent`` or a real subdomain (not a lookalike prefix)."""
    host, parent = host.lower(), parent.lower()
    return host == parent or host.endswith("." + parent)


def blocked_auth_hosts(settings: Settings | None = None) -> set[str]:
    """Hosts whose cookies must never ride along on a site client.

    Always includes the built-in Harvard / Okta / Microsoft hosts, plus any
    configured ``idp_hosts`` / ``sso_hosts``. Configuration adds; it never
    replaces the built-ins (so ``settings=None`` still excludes the IdP).
    """
    hosts = {h.lower() for h in BUILTIN_BLOCKED_HOSTS}
    if settings is not None:
        hosts.update(h.lower() for h in settings.idp_hosts)
        hosts.update(h.lower() for h in settings.sso_hosts)
    else:
        # Fall back to env/defaults so library callers who omit settings still
        # get the configured extras, not an empty block list.
        fallback = Settings.from_env()
        hosts.update(h.lower() for h in fallback.idp_hosts)
        hosts.update(h.lower() for h in fallback.sso_hosts)
    return hosts


def request_host_is_blocked(host: str, blocked: set[str]) -> bool:
    """True when ``host`` is an exact IdP/SSO host (never a suffix match)."""
    return host.lower() in blocked


def cookie_domain_is_blocked(domain: str, blocked: set[str]) -> bool:
    """True when a cookie's Domain must stay out of a site jar.

    Exact IdP/SSO hosts and cookies that would be sent to those hosts are
    excluded. Parent-domain cookies under ``COOKIE_BLOCKED_SUFFIXES``
    (``Domain=.harvard.edu`` / ``Domain=.okta.com``) are also excluded.
    Host-only cookies on a site like ``canvas.harvard.edu`` are NOT blocked
    by the suffix list — that list is only for the parent Domain attribute.
    """
    domain_bare = domain.lstrip(".").lower()
    if not domain_bare:
        return False
    if domain_bare in blocked:
        return True
    if any(cookie_matches_host(domain, b) for b in blocked):
        return True
    if any(cookie_matches_host(b, domain_bare) for b in blocked):
        return True
    # Parent Domain=.harvard.edu / .okta.com only (not every *.harvard.edu host).
    return any(domain_bare == s.lstrip(".") for s in COOKIE_BLOCKED_SUFFIXES)


def host_is_blocked(host: str, blocked: set[str]) -> bool:
    """Back-compat: exact IdP/SSO host check (request/redirect semantics)."""
    return request_host_is_blocked(host, blocked)


def check_request_url(url: str, site_host: str, blocked: set[str]) -> None:
    """Refuse a hop that is not https on the site (or a proper subdomain), or is IdP/SSO.

    Exact IdP/SSO hosts are checked first: a blocked host is allowed only when
    it is exactly ``site_host`` (so ``site=harvard.edu`` still refuses
    ``login.harvard.edu``, while ``site=login.harvard.edu`` allows itself).
    Other proper subdomains of the site remain allowed. Refuses userinfo and
    any port other than the default https port (none or 443).
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    site_host = site_host.lower()
    if parts.scheme != "https" or not host:
        raise NetworkError(f"refusing non-https hop: {parts.scheme or 'no-scheme'}://{host or '?'}")
    if parts.username is not None or parts.password is not None:
        raise NetworkError("refusing URL with userinfo")
    if parts.port is not None and parts.port != 443:
        raise NetworkError(f"refusing non-default https port: {parts.port}")
    # IdP/SSO first: only the exact site host may be a blocked host.
    if request_host_is_blocked(host, blocked):
        if host == site_host:
            return
        raise AuthFailedError(f"signed-out mid-request: redirected to {host} (re-authenticate)")
    if is_proper_subdomain(host, site_host):
        return
    raise NetworkError(f"redirect left {site_host} for {host}")


async def cookies_for_site(
    context: BrowserContext,
    site: str,
    settings: Settings | None = None,
    *,
    include_idp: bool = False,
) -> list[dict[str, Any]]:
    """The cookies from ``context`` that apply to ``site`` (host of an https URL).

    IdP and SSO cookies are excluded unless ``include_idp`` is True, so a
    SharePoint download client never carries Okta session tokens. The built-in
    block list always applies, even when ``settings`` is None.
    """
    host = host_of(site) if "://" in site else site.lower()
    if not host:
        raise ValueError(f"not a host or URL: {site!r}")
    blocked = set() if include_idp else blocked_auth_hosts(settings)
    out: list[dict[str, Any]] = []
    for cookie in await context.cookies():
        domain = cookie.get("domain", "")
        if blocked and cookie_domain_is_blocked(domain, blocked):
            continue
        if not cookie_matches_host(domain, host):
            continue
        out.append(cookie)
    redact.register_cookies(out)
    return out


def filter_site_cookies(
    cookies: list[Mapping[str, Any]],
    site: str,
    settings: Settings | None = None,
    *,
    include_idp: bool = False,
) -> list[dict[str, Any]]:
    """Apply the same site + IdP filter to an already-exported cookie list."""
    host = host_of(site) if "://" in site else site.lower()
    blocked = set() if include_idp else blocked_auth_hosts(settings)
    kept: list[dict[str, Any]] = []
    for cookie in cookies:
        domain = str(cookie.get("domain", ""))
        if blocked and cookie_domain_is_blocked(domain, blocked):
            continue
        if not cookie_matches_host(domain, host):
            continue
        kept.append(dict(cookie))
    redact.register_cookies(kept)
    return kept


def _strict_cookie_policy() -> DefaultCookiePolicy:
    """Host-only cookies (domain_specified=False) must not match subdomains."""
    return DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain)


def apply_strict_cookie_policy(cookies: httpx.Cookies) -> httpx.Cookies:
    """Re-apply host-only policy after httpx copies the jar into a Client."""
    cookies.jar.set_policy(_strict_cookie_policy())
    return cookies


def build_cookie_jar(
    cookies: list[Mapping[str, Any]], site_host: str
) -> tuple[httpx.Cookies, datetime | None]:
    """Build an httpx jar that preserves Secure and host-only scope."""
    jar = httpx.Cookies()
    jar.jar.set_policy(_strict_cookie_policy())
    expires_at: datetime | None = None
    for cookie in cookies:
        raw_domain = str(cookie.get("domain") or site_host)
        initial_dot = raw_domain.startswith(".")
        domain = raw_domain.lstrip(".").lower()
        # Leading dot from Playwright => Domain attribute was set (not host-only).
        host_only = not initial_dot
        exp_raw = cookie.get("expires")
        exp: int | None
        if isinstance(exp_raw, (int, float)) and exp_raw > 0:
            exp = int(exp_raw)
            when = datetime.fromtimestamp(exp, tz=UTC)
            expires_at = when if expires_at is None else min(expires_at, when)
        else:
            exp = None
        cj = Cookie(
            version=0,
            name=str(cookie["name"]),
            value=str(cookie["value"]),
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=not host_only,
            domain_initial_dot=initial_dot,
            path=str(cookie.get("path") or "/"),
            path_specified=True,
            secure=bool(cookie.get("secure", False)),
            expires=exp,
            discard=exp is None,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": ""} if cookie.get("httpOnly") else {},
            rfc2109=False,
        )
        jar.jar.set_cookie(cj)
    return jar, expires_at


def _sanitize_redirect_headers(
    headers: httpx.Headers, *, prev_host: str, next_host: str
) -> dict[str, str]:
    """Headers for the next hop: drop Cookie; drop Authorization on host change.

    The jar recomputes Cookie per URL via ``client.build_request``. Copying the
    previous Cookie header would send host-only cookies to a subdomain and
    ignore Set-Cookie from the redirect response.
    """
    out: dict[str, str] = {}
    for key, value in headers.multi_items():
        low = key.lower()
        if low in {"cookie", "content-length", "content-type", "host"}:
            continue
        if low == "authorization" and prev_host.lower() != next_host.lower():
            continue
        out[key] = value
    return out


def _attach_redirect_guard(
    client: httpx.AsyncClient,
    site_host: str,
    blocked: set[str],
) -> httpx.AsyncClient:
    """Replace ``client.send`` with a manual redirect loop that checks each hop first."""
    original = client.send

    async def gated_send(request: httpx.Request, **kwargs: Any) -> httpx.Response:
        kwargs = dict(kwargs)
        kwargs["follow_redirects"] = False
        current = request
        for _ in range(MAX_REDIRECTS + 1):
            check_request_url(str(current.url), site_host, blocked)
            # httpx's build_request copies the jar and drops DomainStrictNonDomain,
            # so host-only cookies would leak to subdomains. Recompute Cookie from
            # our policy-bearing client jar immediately before each send.
            apply_strict_cookie_policy(client.cookies)
            if "cookie" in current.headers:
                del current.headers["cookie"]
            client.cookies.set_cookie_header(current)
            response = await original(current, **kwargs)
            # Let the jar see Set-Cookie on this response before the next hop.
            client.cookies.extract_cookies(response)
            apply_strict_cookie_policy(client.cookies)
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = str(httpx.URL(current.url).join(location))
            try:
                check_request_url(next_url, site_host, blocked)
            except (AuthFailedError, NetworkError):
                await response.aclose()
                raise
            await response.aclose()
            if response.status_code in (307, 308):
                method = current.method
                content = current.content
            else:
                method = "GET"
                content = b""
            prev_host = current.url.host or ""
            next_host = httpx.URL(next_url).host or ""
            headers = _sanitize_redirect_headers(
                current.headers, prev_host=prev_host, next_host=next_host
            )
            # build_request lets the jar compute Cookie for this URL (host-only
            # scope + any Set-Cookie from the redirect response).
            current = client.build_request(method, next_url, headers=headers, content=content)
        raise NetworkError(f"too many redirects (>{MAX_REDIRECTS}) while fetching {site_host}")

    client.send = gated_send  # type: ignore[method-assign]
    return client


def _build_guarded_client(
    cookies: list[Mapping[str, Any]],
    site: str,
    *,
    settings: Settings | None,
    include_idp: bool,
    timeout_s: float,
) -> httpx.AsyncClient:
    host = host_of(site) if "://" in site else site.lower()
    if not host:
        raise ValueError(f"not a host or URL: {site!r}")
    kept = filter_site_cookies(list(cookies), site, settings, include_idp=include_idp)
    jar, expires_at = build_cookie_jar(kept, host)
    blocked = set() if include_idp else blocked_auth_hosts(settings)
    client = httpx.AsyncClient(
        cookies=jar,
        follow_redirects=False,
        timeout=timeout_s,
        headers={"User-Agent": "crimson-headless-passkey/0.3"},
    )
    # httpx copies cookies into a fresh jar and drops our policy; re-apply.
    apply_strict_cookie_policy(client.cookies)
    client.extensions = {"expires_at": expires_at, "site": host}  # type: ignore[attr-defined]
    return _attach_redirect_guard(client, host, blocked)


async def http_client(
    source: SignedIn | BrowserContext,
    site: str,
    *,
    settings: Settings | None = None,
    include_idp: bool = False,
    timeout_s: float = 60,
) -> httpx.AsyncClient:
    """An in-memory ``httpx.AsyncClient`` carrying the cookies for ``site``.

    Nothing is written to disk. Redirects are followed manually (at most
    ``MAX_REDIRECTS`` hops); each hop must be https on the site host or a
    proper subdomain, and never an IdP/SSO host. The check runs before the
    request is sent.
    """
    if isinstance(source, SignedIn):
        context, settings = source.context, settings or source.settings
    else:
        context = source
    cookies = await cookies_for_site(context, site, settings, include_idp=include_idp)
    return _build_guarded_client(
        cookies, site, settings=settings, include_idp=include_idp, timeout_s=timeout_s
    )


def http_client_from_cookies(
    cookies: list[Mapping[str, Any]],
    site: str,
    *,
    settings: Settings | None = None,
    include_idp: bool = False,
    timeout_s: float = 60,
) -> httpx.AsyncClient:
    """Build a guarded client from an already-exported cookie list (no Playwright)."""
    return _build_guarded_client(
        list(cookies), site, settings=settings, include_idp=include_idp, timeout_s=timeout_s
    )


def save_cookies(
    cookies: list[Mapping[str, Any]],
    path: Path,
    *,
    site: str,
    settings: Settings | None = None,
    force: bool = False,
) -> None:
    """Write cookies for ``site`` with mode 0600. Explicit opt-in only.

    Applies the IdP/SSO filter itself. Refuses to overwrite an existing file
    unless ``force`` is True. See SECURITY.md.
    """
    path = Path(path)
    if path.exists() and not force:
        raise ConfigError(
            f"{path} already exists; pass --force (or force=True) to overwrite a cookies file"
        )
    host = host_of(site) if "://" in site else site.lower()
    kept = filter_site_cookies(list(cookies), site, settings, include_idp=False)
    fields = ("name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite")
    payload = {
        "site": host,
        "cookies": [{k: c[k] for k in fields if k in c} for c in kept],
        "savedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    storage.write_private_json(path, payload)
