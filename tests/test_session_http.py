"""Cookie export stays in memory; redirect guard refuses bad hops before sending."""

from __future__ import annotations

import asyncio
import json
import stat

import httpx
import pytest
from playwright.async_api import async_playwright

from crimson_headless_passkey import session
from crimson_headless_passkey.config import Settings
from crimson_headless_passkey.errors import AuthFailedError, ConfigError, NetworkError

pytestmark = pytest.mark.browser


def run(coro):
    return asyncio.run(coro)


async def _context_with_cookies(browser, cookies):
    context = await browser.new_context()
    await context.add_cookies(cookies)
    return context


SITE = "https://contoso.sharepoint.com/sites/X"
SITE_HOST = "contoso.sharepoint.com"


def test_http_client_jar_contains_only_site_cookies(tmp_path):
    async def go():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await _context_with_cookies(
                    browser,
                    [
                        {
                            "name": "FedAuth",
                            "value": "sharepoint-secret-value-001",
                            "domain": SITE_HOST,
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "sid",
                            "value": "okta-session-secret-002",
                            "domain": "login.harvard.edu",
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "parent",
                            "value": "harvard-parent-secret-003",
                            "domain": ".harvard.edu",
                            "path": "/",
                            "secure": True,
                        },
                    ],
                )
                settings = Settings.from_env(data_dir=tmp_path, env={})
                client = await session.http_client(context, SITE, settings=settings)
                try:
                    names = {c.name for c in client.cookies.jar}
                    assert names == {"FedAuth"}
                    for c in client.cookies.jar:
                        assert c.secure is True
                        assert c.value == "sharepoint-secret-value-001"
                finally:
                    await client.aclose()
            finally:
                await browser.close()

    run(go())


def test_harvard_edu_parent_cookie_is_excluded(tmp_path):
    async def go():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await _context_with_cookies(
                    browser,
                    [
                        {
                            "name": "campus",
                            "value": "parentcookievalueXYZ999",
                            "domain": ".harvard.edu",
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "FedAuth",
                            "value": "sp-ok-001aaaaaaaa",
                            "domain": SITE_HOST,
                            "path": "/",
                            "secure": True,
                        },
                    ],
                )
                cookies = await session.cookies_for_site(context, SITE, None)
                assert {c["name"] for c in cookies} == {"FedAuth"}
            finally:
                await browser.close()

    run(go())


def test_lookalike_host_cookie_is_excluded(tmp_path):
    async def go():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await _context_with_cookies(
                    browser,
                    [
                        {
                            "name": "evil",
                            "value": "lookalike-secret-value-004",
                            "domain": "evilcontoso.sharepoint.com",
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "FedAuth",
                            "value": "sp-ok-002bbbbbbbb",
                            "domain": SITE_HOST,
                            "path": "/",
                            "secure": True,
                        },
                    ],
                )
                cookies = await session.cookies_for_site(context, SITE, None)
                assert {c["name"] for c in cookies} == {"FedAuth"}
            finally:
                await browser.close()

    run(go())


def test_settings_none_still_excludes_idp_cookies(tmp_path):
    async def go():
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await _context_with_cookies(
                    browser,
                    [
                        {
                            "name": "FedAuth",
                            "value": "sp-ok-003cccccccc",
                            "domain": SITE_HOST,
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "sid",
                            "value": "okta-session-secret-005",
                            "domain": "login.harvard.edu",
                            "path": "/",
                            "secure": True,
                        },
                        {
                            "name": "ESTSAUTH",
                            "value": "ms-session-secret-006",
                            "domain": "login.microsoftonline.com",
                            "path": "/",
                            "secure": True,
                        },
                    ],
                )
                cookies = await session.cookies_for_site(context, SITE, settings=None)
                assert {c["name"] for c in cookies} == {"FedAuth"}
            finally:
                await browser.close()

    run(go())


def _redirect_cases():
    return [
        ("https://evil.example/steal", "off-host"),
        ("http://contoso.sharepoint.com/insecure", "http"),
        ("https://login.harvard.edu/login", "idp"),
        ("https://evilcontoso.sharepoint.com/x", "lookalike"),
    ]


@pytest.mark.parametrize("location,kind", _redirect_cases())
def test_redirect_refused_before_sending(location, kind):
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        if request.url.path.endswith("/start"):
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(200, text="should-not-reach")

    transport = httpx.MockTransport(handler)
    cookies = [
        {
            "name": "FedAuth",
            "value": "sp-ok-004dddddddd",
            "domain": SITE_HOST,
            "path": "/",
            "secure": True,
        }
    ]
    client = session.http_client_from_cookies(cookies, SITE)
    # Swap in the mock transport while keeping the redirect guard on send.
    client._transport = transport

    async def go():
        with pytest.raises((NetworkError, AuthFailedError)):
            await client.get(f"https://{SITE_HOST}/start")
        await client.aclose()

    run(go())
    assert sent == [f"https://{SITE_HOST}/start"], (
        f"forbidden hop ({kind}) must never be sent; got {sent}"
    )


def test_save_cookies_is_0600_applies_idp_filter_and_refuses_overwrite(tmp_path):
    path = tmp_path / "cookies.json"
    cookies = [
        {"name": "FedAuth", "value": "abc123XYZ999secret", "domain": "sp.example", "path": "/"},
        {"name": "sid", "value": "othersecret999", "domain": "login.harvard.edu", "path": "/"},
    ]
    session.save_cookies(cookies, path, site="https://sp.example/sites/X")
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data["site"] == "sp.example"
    assert [c["name"] for c in data["cookies"]] == ["FedAuth"]
    with pytest.raises(ConfigError, match="already exists"):
        session.save_cookies(cookies, path, site="https://sp.example/sites/X")
    session.save_cookies(cookies, path, site="https://sp.example/sites/X", force=True)


def test_http_client_from_cookies_has_guard():
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://login.live.com/x"})

    client = session.http_client_from_cookies(
        [
            {
                "name": "a",
                "value": "bsecret999111",
                "domain": "example.com",
                "path": "/",
                "secure": True,
            }
        ],
        "https://example.com/",
    )
    client._transport = httpx.MockTransport(handler)

    async def go():
        with pytest.raises(AuthFailedError):
            await client.get("https://example.com/start")
        await client.aclose()

    run(go())
    assert sent == ["https://example.com/start"]


def test_is_proper_subdomain_rejects_lookalikes():
    assert session.is_proper_subdomain("contoso.sharepoint.com", "contoso.sharepoint.com")
    assert session.is_proper_subdomain("a.contoso.sharepoint.com", "contoso.sharepoint.com")
    assert not session.is_proper_subdomain("evilcontoso.sharepoint.com", "contoso.sharepoint.com")


def test_host_only_cookie_not_sent_to_subdomain_direct_and_redirect():
    """Host-only cookies must not appear on subdomain requests (A)."""
    recorded: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append((str(request.url), request.headers.get("cookie")))
        if request.url.path == "/start":
            return httpx.Response(
                302, headers={"Location": "https://sub.contoso.sharepoint.com/next"}
            )
        return httpx.Response(200, text="ok")

    cookies = [
        {
            "name": "hostonly",
            "value": "host-only-secret-AAA111",
            "domain": SITE_HOST,  # no leading dot => host-only
            "path": "/",
            "secure": True,
        },
        {
            "name": "scoped",
            "value": "domain-scoped-secret-BBB222",
            "domain": "." + SITE_HOST,
            "path": "/",
            "secure": True,
        },
    ]
    client = session.http_client_from_cookies(cookies, SITE)
    client._transport = httpx.MockTransport(handler)

    async def go():
        # Direct subdomain request: host-only must be absent; domain cookie may be present.
        r = await client.get(f"https://sub.{SITE_HOST}/direct")
        assert r.status_code == 200
        # Redirect from site host to subdomain.
        r = await client.get(f"https://{SITE_HOST}/start")
        assert r.status_code == 200
        await client.aclose()

    run(go())
    by_url = {u: c for u, c in recorded}
    direct = by_url[f"https://sub.{SITE_HOST}/direct"] or ""
    assert "hostonly=" not in direct, f"host-only leaked on direct subdomain: {direct}"
    assert "scoped=" in direct
    start = by_url[f"https://{SITE_HOST}/start"] or ""
    assert "hostonly=" in start
    nxt = by_url[f"https://sub.{SITE_HOST}/next"] or ""
    assert "hostonly=" not in nxt, f"host-only leaked after redirect: {nxt}"
    assert "scoped=" in nxt


def test_redirect_rebuilds_cookies_and_strips_authorization_on_host_change():
    """Cookie not copied; Set-Cookie on redirect used; Auth drops on host change (B)."""
    recorded: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append(
            {
                "url": str(request.url),
                "cookie": request.headers.get("cookie"),
                "authorization": request.headers.get("authorization"),
            }
        )
        if request.url.path == "/hop1":
            return httpx.Response(
                302,
                headers={
                    "Location": "https://a.contoso.sharepoint.com/hop2",
                    "Set-Cookie": (
                        "from_redirect=redirect-secret-CCC333; "
                        "Domain=.contoso.sharepoint.com; Path=/; Secure"
                    ),
                },
            )
        if request.url.path == "/hop2":
            return httpx.Response(
                302,
                headers={"Location": "https://b.contoso.sharepoint.com/hop3"},
            )
        return httpx.Response(200, text="done")

    cookies = [
        {
            "name": "start",
            "value": "start-secret-DDD444",
            "domain": "." + SITE_HOST,
            "path": "/",
            "secure": True,
        }
    ]
    client = session.http_client_from_cookies(cookies, SITE)
    client._transport = httpx.MockTransport(handler)

    async def go():
        r = await client.get(
            f"https://{SITE_HOST}/hop1",
            headers={"Authorization": "Bearer keep-or-drop-secret-EEE555"},
        )
        assert r.status_code == 200
        await client.aclose()

    run(go())
    assert len(recorded) == 3
    hop1, hop2, hop3 = recorded
    assert hop1["authorization"] == "Bearer keep-or-drop-secret-EEE555"
    assert "start=" in (hop1["cookie"] or "")
    # Same site family but host changed a.contoso... from contoso... => Auth dropped.
    assert hop2["authorization"] is None, hop2
    assert "from_redirect=" in (hop2["cookie"] or ""), hop2
    assert "start=" in (hop2["cookie"] or "")
    assert hop3["authorization"] is None
    assert "from_redirect=" in (hop3["cookie"] or "")


def test_authorization_kept_on_same_host_redirect():
    recorded: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        recorded.append(request.headers.get("authorization"))
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": f"https://{SITE_HOST}/b"})
        return httpx.Response(200)

    client = session.http_client_from_cookies(
        [
            {
                "name": "x",
                "value": "ysecret999111aaa",
                "domain": SITE_HOST,
                "path": "/",
                "secure": True,
            }
        ],
        SITE,
    )
    client._transport = httpx.MockTransport(handler)

    async def go():
        await client.get(
            f"https://{SITE_HOST}/a", headers={"Authorization": "Bearer same-host-secret-FFF666"}
        )
        await client.aclose()

    run(go())
    assert recorded == [
        "Bearer same-host-secret-FFF666",
        "Bearer same-host-secret-FFF666",
    ]


def test_canvas_harvard_edu_allowed_as_site_with_filtered_cookies(tmp_path):
    """Regression: *.harvard.edu is NOT refused as a request target; IdP cookies stay out."""
    site = "https://canvas.harvard.edu/courses/1"
    sent: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((str(request.url), request.headers.get("cookie")))
        if request.url.path.endswith("/start"):
            return httpx.Response(302, headers={"Location": "https://login.harvard.edu/login"})
        return httpx.Response(200, text="canvas-ok")

    cookies = [
        {
            "name": "canvas_session",
            "value": "canvas-host-only-secret-GGG777",
            "domain": "canvas.harvard.edu",
            "path": "/",
            "secure": True,
        },
        {
            "name": "parent",
            "value": "harvard-parent-secret-HHH888",
            "domain": ".harvard.edu",
            "path": "/",
            "secure": True,
        },
        {
            "name": "sid",
            "value": "idp-session-secret-III999",
            "domain": "login.harvard.edu",
            "path": "/",
            "secure": True,
        },
        {
            "name": "key",
            "value": "key-harvard-secret-JJJ000",
            "domain": "key.harvard.edu",
            "path": "/",
            "secure": True,
        },
    ]
    client = session.http_client_from_cookies(cookies, site, settings=None)
    names = {c.name for c in client.cookies.jar}
    assert names == {"canvas_session"}, names
    client._transport = httpx.MockTransport(handler)

    async def go():
        r = await client.get("https://canvas.harvard.edu/")
        assert r.status_code == 200
        with pytest.raises(AuthFailedError):
            await client.get("https://canvas.harvard.edu/start")
        await client.aclose()

    run(go())
    assert sent[0][0] == "https://canvas.harvard.edu/"
    assert "canvas_session=" in (sent[0][1] or "")
    assert "parent=" not in (sent[0][1] or "")
    # IdP hop never sent
    assert all("login.harvard.edu" not in u for u, _ in sent)


def test_check_request_url_refuses_userinfo_and_non_443_port():
    blocked = session.blocked_auth_hosts(None)
    with pytest.raises(NetworkError, match="userinfo"):
        session.check_request_url("https://user:pass@contoso.sharepoint.com/x", SITE_HOST, blocked)
    with pytest.raises(NetworkError, match="port"):
        session.check_request_url("https://contoso.sharepoint.com:8443/x", SITE_HOST, blocked)
    # Default https (no port) and explicit 443 are fine.
    session.check_request_url(f"https://{SITE_HOST}/", SITE_HOST, blocked)
    session.check_request_url(f"https://{SITE_HOST}:443/", SITE_HOST, blocked)


def test_site_harvard_edu_refuses_login_harvard_edu():
    """IdP block runs before subdomain allow: site=harvard.edu ≠ login.harvard.edu."""
    blocked = session.blocked_auth_hosts(None)
    with pytest.raises(AuthFailedError, match="signed-out"):
        session.check_request_url("https://login.harvard.edu/login", "harvard.edu", blocked)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "https://login.harvard.edu/x"})
        return httpx.Response(200)

    client = session.http_client_from_cookies(
        [
            {
                "name": "c",
                "value": "campus-secret-KKK111",
                "domain": "harvard.edu",
                "path": "/",
                "secure": True,
            }
        ],
        "https://harvard.edu/",
    )
    client._transport = httpx.MockTransport(handler)

    async def go():
        with pytest.raises(AuthFailedError, match="signed-out"):
            await client.get("https://harvard.edu/start")
        await client.aclose()

    run(go())
    assert sent == ["https://harvard.edu/start"]
    assert all("login.harvard.edu" not in u for u in sent)


def test_site_login_harvard_edu_allows_itself():
    """The IdP host is allowed only when it is exactly the chosen site."""
    blocked = session.blocked_auth_hosts(None)
    session.check_request_url("https://login.harvard.edu/", "login.harvard.edu", blocked)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    client = session.http_client_from_cookies(
        [
            {
                "name": "sid",
                "value": "idp-self-secret-LLL222",
                "domain": "login.harvard.edu",
                "path": "/",
                "secure": True,
            }
        ],
        "https://login.harvard.edu/",
        include_idp=True,
    )
    client._transport = httpx.MockTransport(handler)

    async def go():
        r = await client.get("https://login.harvard.edu/")
        assert r.status_code == 200
        await client.aclose()

    run(go())
    assert sent == ["https://login.harvard.edu/"]


def test_key_harvard_edu_is_exact_idp_signed_out():
    """key.harvard.edu is an exact IdP host → AuthFailedError (signed out), not NetworkError."""
    blocked = session.blocked_auth_hosts(None)
    assert "key.harvard.edu" in blocked
    with pytest.raises(AuthFailedError, match="signed-out"):
        session.check_request_url("https://key.harvard.edu/login", "canvas.harvard.edu", blocked)
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "https://key.harvard.edu/x"})
        return httpx.Response(200)

    client = session.http_client_from_cookies(
        [
            {
                "name": "c",
                "value": "canvas-secret-MMM333",
                "domain": "canvas.harvard.edu",
                "path": "/",
                "secure": True,
            }
        ],
        "https://canvas.harvard.edu/",
    )
    client._transport = httpx.MockTransport(handler)

    async def go():
        with pytest.raises(AuthFailedError, match="signed-out"):
            await client.get("https://canvas.harvard.edu/start")
        await client.aclose()

    run(go())
    assert sent == ["https://canvas.harvard.edu/start"]
