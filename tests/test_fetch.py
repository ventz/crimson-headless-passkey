"""Offline fetch against a fake IdP + fake SharePoint (httpx MockTransport / loopback)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

import crimson_headless_passkey.downloader as fetch_mod
from crimson_headless_passkey import pathsafe, sharepoint, storage
from crimson_headless_passkey.config import Settings
from crimson_headless_passkey.errors import RefusedURLError
from crimson_headless_passkey.exitcodes import (
    STATUS_OK,
)

pytestmark = pytest.mark.browser

APP = "https://app.example"
IDP = "https://idp.example"
SP = "https://contoso.sharepoint.com"

HELPERS = """
const b = s => Uint8Array.from(s, c => c.charCodeAt(0));
const challenge = b("0123456789abcdef");
const assertion = () => navigator.credentials.get({publicKey: {
    challenge, rpId: "idp.example", userVerification: "required", timeout: 2000,
}});
"""

TREE = {
    "/sites/Docs/Shared Documents": {
        "folders": ["Sub"],
        "files": {"readme.txt": b"hello root", "a.bin": b"AAAA"},
    },
    "/sites/Docs/Shared Documents/Sub": {
        "folders": [],
        "files": {"nested.txt": b"hello nested"},
    },
}


def _folder_json(path: str) -> dict:
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return {
        "Name": name,
        "ServerRelativeUrl": path,
        "UniqueId": "11111111-1111-1111-1111-111111111111",
        "TimeLastModified": "2026-01-01T00:00:00Z",
        "ItemCount": 1,
    }


def _file_json(path: str, body: bytes) -> dict:
    name = path.rsplit("/", 1)[-1]
    return {
        "Name": name,
        "ServerRelativeUrl": path,
        "Length": len(body),
        "UniqueId": "22222222-2222-2222-2222-222222222222",
        "ETag": f'"{len(body)}-{name}"',
        "TimeLastModified": "2026-01-01T00:00:00Z",
    }


def sp_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    path = request.url.path
    # List / get folder
    if "GetFolderByServerRelativeUrl" in path and path.endswith("/Files"):
        # extract folder path from '...(\'PATH\')/Files'
        import re

        m = re.search(r"GetFolderByServerRelativeUrl\('([^']+)'\)/Files", path)
        folder = m.group(1) if m else ""
        files = TREE.get(folder, {}).get("files", {})
        return httpx.Response(
            200,
            json={"value": [_file_json(f"{folder}/{n}", b) for n, b in files.items()]},
        )
    if "GetFolderByServerRelativeUrl" in path and path.endswith("/Folders"):
        import re

        m = re.search(r"GetFolderByServerRelativeUrl\('([^']+)'\)/Folders", path)
        folder = m.group(1) if m else ""
        names = TREE.get(folder, {}).get("folders", [])
        return httpx.Response(
            200,
            json={"value": [_folder_json(f"{folder}/{n}") for n in names]},
        )
    if "GetFolderByServerRelativeUrl" in path:
        import re

        m = re.search(r"GetFolderByServerRelativeUrl\('([^']+)'\)", path)
        folder = m.group(1) if m else ""
        if folder in TREE:
            return httpx.Response(200, json=_folder_json(folder))
        return httpx.Response(404, json={})
    if "GetFileByServerRelativeUrl" in path and path.endswith("/$value"):
        import re
        import urllib.parse

        m = re.search(r"GetFileByServerRelativeUrl\('([^']+)'\)/\$value", path)
        rel = urllib.parse.unquote(m.group(1)) if m else ""
        folder, _, name = rel.rpartition("/")
        body = TREE.get(folder, {}).get("files", {}).get(name)
        if body is None:
            return httpx.Response(404)
        range_h = request.headers.get("range")
        if range_h and range_h.startswith("bytes="):
            start = int(range_h.split("=")[1].split("-")[0] or 0)
            return httpx.Response(
                206,
                content=body[start:],
                headers={"Content-Range": f"bytes {start}-{len(body) - 1}/{len(body)}"},
            )
        return httpx.Response(200, content=body)
    if "GetFileByServerRelativeUrl" in path:
        import re
        import urllib.parse

        m = re.search(r"GetFileByServerRelativeUrl\('([^']+)'\)", path)
        rel = urllib.parse.unquote(m.group(1)) if m else ""
        folder, _, name = rel.rpartition("/")
        body = TREE.get(folder, {}).get("files", {}).get(name)
        if body is None:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=_file_json(rel, body))
    if "GetFileById" in path and path.endswith("/$value"):
        # any id -> readme
        body = b"hello root"
        return httpx.Response(200, content=body)
    return httpx.Response(404, json={"error": url})


async def enroll_and_context(browser, settings):
    from crimson_headless_passkey.authenticator import VirtualAuthenticator

    context = await browser.new_context()

    async def serve(route):
        u = route.request.url.split("?")[0]
        pages = {
            f"{SP}/sites/Docs/Shared%20Documents/Forms/AllItems.aspx": (
                "<html><body>folder</body></html>"
            ),
            f"{IDP}/enroll": f"<script>{HELPERS}"
            "window.enroll=()=>navigator.credentials.create({publicKey:{"
            "challenge,rp:{id:'idp.example',name:'Fake'},"
            "user:{id:b('u'),name:'someone',displayName:'S'},"
            "pubKeyCredParams:[{type:'public-key',alg:-7}],"
            "authenticatorSelection:{residentKey:'required',userVerification:'required'}"
            "}}).then(()=>{location='https://app.example/home'});</script>",
            f"{IDP}/login": f"<script>{HELPERS}"
            "assertion().then(()=>{{"
            "location='{SP}/sites/Docs/Shared%20Documents/Forms/AllItems.aspx?id=/sites/Docs/Shared%20Documents';}});</script>".format(
                SP=SP
            ),
            f"{APP}/home": "<h1>ok</h1>",
            f"{SP}/sites/Docs": f"<script>location='{IDP}/login'</script>",
        }
        # Fix the login page - set cookie on response via fulfill is hard for other domain.
        # Instead: after sign-in the test injects cookies itself.
        if u == f"{IDP}/login":
            body = (
                f"<script>{HELPERS}"
                "assertion().then(()=>{location='"
                f"{SP}/sites/Docs/Shared%20Documents/Forms/AllItems.aspx"
                "?id=/sites/Docs/Shared Documents';});</script>"
            )
            await route.fulfill(status=200, content_type="text/html", body=body)
            return
        if u.startswith(SP) and "AllItems" in u:
            await route.fulfill(status=200, content_type="text/html", body="<h1>sp</h1>")
            return
        if u in pages:
            await route.fulfill(status=200, content_type="text/html", body=pages[u])
            return
        if u == f"{IDP}/enroll" or u.endswith("/enroll"):
            await route.fulfill(status=200, content_type="text/html", body=pages[f"{IDP}/enroll"])
            return
        await route.fulfill(status=404, body="")

    await context.route("https://**/*", serve)
    # Enroll
    page = await context.new_page()
    await page.goto(f"{IDP}/enroll")
    authn = await VirtualAuthenticator.attach(context, page)
    await page.evaluate("enroll()")
    await page.wait_for_url(f"{APP}/home")
    storage.save_credentials(settings.credential_file, authn.added)
    await authn.detach()
    await page.close()
    return context


def fake_settings(tmp_path, **kw):
    values = dict(
        data_dir=tmp_path,
        rp_id="idp.example",
        idp_hosts=["idp.example"],
        sso_hosts=["login.microsoftonline.com"],
        env={},
    )
    values.update(kw)
    return Settings.from_env(**values)


def test_path_guard_on_sharepoint_names(tmp_path):
    """SharePoint names with .. are rejected before any open."""
    with pytest.raises(pathsafe.UnsafePathError):
        pathsafe.safe_target(tmp_path, "../secret.txt")


def test_peoplesoft_url_refused(tmp_path):
    settings = fake_settings(tmp_path)
    with pytest.raises(RefusedURLError):
        asyncio.run(fetch_mod.fetch("https://peoplesoft.harvard.edu/", tmp_path, settings=settings))


def test_sharepoint_resolve_and_walk_with_mock():
    async def go():
        transport = httpx.MockTransport(sp_handler)
        async with httpx.AsyncClient(transport=transport, base_url=SP) as client:
            target = await sharepoint.resolve(
                client,
                f"{SP}/sites/Docs/Shared%20Documents/Forms/AllItems.aspx"
                "?id=/sites/Docs/Shared Documents",
            )
            assert target.is_folder
            files = [rel async for rel, _ in sharepoint.walk(client, target.site_url, target.item)]
            assert sorted(files) == ["Sub/nested.txt", "a.bin", "readme.txt"]

    asyncio.run(go())


def test_stream_resume_and_skip(tmp_path):
    async def go():
        transport = httpx.MockTransport(sp_handler)
        out = tmp_path / "out"
        out.mkdir()
        async with httpx.AsyncClient(transport=transport) as client:
            item = sharepoint.SpItem(
                name="readme.txt",
                server_relative_url="/sites/Docs/Shared Documents/readme.txt",
                kind="file",
                length=10,
                unique_id="22222222-2222-2222-2222-222222222222",
                etag='"10-readme.txt"',
                modified="2026-01-01T00:00:00Z",
            )
            url = sharepoint.download_url(SP, item)
            # Partial .part then resume
            target = pathsafe.safe_target(out, "readme.txt")
            part = pathsafe.part_path(target)
            pathsafe.make_parents(out.resolve(), target)
            fd = pathsafe.open_for_write(out.resolve(), part)
            os_write = __import__("os").write
            os_write(fd, b"hello")
            __import__("os").close(fd)
            n = await fetch_mod._stream_to(
                client, url, out.resolve(), target, resume=True, expected=10
            )
            assert target.read_bytes() == b"hello root"
            assert n == 10
            # Manifest skip
            manifest = {
                "version": 1,
                "files": {
                    "readme.txt": {
                        "etag": item.etag,
                        "length": 10,
                        "unique_id": item.unique_id,
                        "modified": item.modified,
                    }
                },
            }
            assert fetch_mod.should_skip(target, manifest["files"]["readme.txt"], item)

    asyncio.run(go())


def test_fetch_report_status_line():
    r = fetch_mod.FetchReport(
        ok=True,
        status=STATUS_OK,
        url="https://x",
        out_dir=Path("/tmp"),
        fetched=2,
        skipped=3,
        failed=0,
        bytes=1024,
        elapsed_s=1.5,
    )
    line = r.status_line()
    assert "fetched=2" in line and "skipped=3" in line and "code=0" in line


def test_manifest_round_trip(tmp_path):
    fetch_mod.save_manifest(tmp_path, {"version": 1, "files": {"a": {"length": 1}}})
    assert fetch_mod.load_manifest(tmp_path)["files"]["a"]["length"] == 1


class _StopAtSignIn(Exception):
    pass


def _capture_signed_in(monkeypatch):
    seen = {}

    def fake_signed_in(url, settings, **kwargs):
        seen.update(kwargs)
        raise _StopAtSignIn

    monkeypatch.setattr(fetch_mod.session, "signed_in", fake_signed_in)
    return seen


def test_fetch_does_not_save_the_session_by_default(tmp_path, monkeypatch):
    seen = _capture_signed_in(monkeypatch)
    settings = Settings.from_env(env={}, data_dir=tmp_path / "data")
    with pytest.raises(_StopAtSignIn):
        asyncio.run(fetch_mod.fetch(f"{APP}/file.txt", tmp_path / "out", settings=settings))
    assert seen["save_state"] is False
    assert seen["use_saved_state"] is True


@pytest.mark.parametrize(
    ("flags", "expected"),
    [([], False), (["--no-save-state"], False), (["--save-state"], True)],
)
@pytest.mark.parametrize("entry", ["crimson-headless-passkey", "harvard-fetch"])
def test_fetch_cli_saves_the_session_only_with_save_state(
    tmp_path, monkeypatch, entry, flags, expected
):
    from crimson_headless_passkey import cli

    seen = {}

    async def fake_fetch(url, out_dir, **kwargs):
        seen.update(kwargs)
        return fetch_mod.FetchReport(ok=True, status=STATUS_OK, url=url, out_dir=Path(out_dir))

    monkeypatch.setattr(cli.downloader, "fetch", fake_fetch)
    monkeypatch.chdir(tmp_path)  # no ./.env from the repo
    args = [f"{APP}/file.txt", "--out", str(tmp_path / "out"), "--data-dir", str(tmp_path / "d")]
    if entry == "harvard-fetch":
        code = cli.fetch_main([*args, *flags])
    else:
        code = cli.main(["fetch", *args, *flags])
    assert code == 0
    assert seen["save_state"] is expected


def test_fetch_cli_rejects_save_state_with_no_save_state(tmp_path):
    from crimson_headless_passkey import cli

    with pytest.raises(SystemExit):
        cli.fetch_main([f"{APP}/f", "--out", str(tmp_path), "--save-state", "--no-save-state"])
