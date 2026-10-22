"""Resolve a SharePoint / OneDrive URL and enumerate / download via SharePoint REST.

Primary path: SharePoint REST v1 (GET only, no request digest). Cookie auth
from the signed-in session. Fallback for sharing links: ``/_api/v2.0/shares``.

All request bodies are JSON or streaming bytes; nothing is logged. Errors are
mapped to ``NotFoundError``, ``AuthFailedError`` or ``NetworkError``.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import httpx

from . import redact
from .errors import AuthFailedError, NetworkError, NotFoundError

# Classic folder view: AllItems.aspx?id=/sites/X/Shared Documents/Folder
ID_PARAM = re.compile(r"[?&]id=([^&]+)", re.IGNORECASE)
# Modern sharing link: /:f:/r/sites/... or /:x:/r/...
MODERN = re.compile(r"/:[a-z]:/[a-z]/(.+)$", re.IGNORECASE)
# Doc.aspx?sourcedoc={GUID}
SOURCEDOC = re.compile(
    r"[?&]sourcedoc=(\{?[0-9A-Fa-f-]{32,}\}?)|%7[Bb]([0-9A-Fa-f-]{32,})%7[Dd]", re.I
)
GUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


@dataclass
class SpItem:
    """One file or folder on a SharePoint / OneDrive site."""

    name: str
    server_relative_url: str
    kind: str  # "file" or "folder"
    length: int | None = None
    unique_id: str | None = None
    etag: str | None = None
    modified: str | None = None
    children: list[SpItem] = field(default_factory=list)


@dataclass
class SpTarget:
    """What a URL points at, after resolution."""

    site_url: str  # https://tenant.sharepoint.com/sites/Site
    host: str
    item: SpItem
    is_folder: bool


def site_root(url: str) -> str:
    """``https://host/sites/Name`` (or ``/teams/Name``, or the host root)."""
    parts = urlsplit(url)
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) >= 2 and segments[0].lower() in ("sites", "teams", "personal"):
        path = "/" + "/".join(segments[:2])
    else:
        path = ""
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def parse_url(url: str) -> tuple[str, str | None, str | None]:
    """Return ``(site_url, server_relative_path|None, unique_id|None)`` from a SharePoint URL."""
    parts = urlsplit(url)
    site = site_root(url)
    path = unquote(parts.path)
    m = ID_PARAM.search(url)
    if m:
        return site, unquote(m.group(1)), None
    m = SOURCEDOC.search(url)
    if m:
        guid = (m.group(1) or m.group(2) or "").strip("{}")
        return site, None, guid
    m = MODERN.search(path)
    if m:
        return site, "/" + m.group(1).lstrip("/"), None
    # Direct library path: /sites/X/Shared Documents/file.pdf
    # Drop query; keep a direct library path as server-relative.
    if path and not path.endswith(".aspx") and path != "/":
        return site, path, None
    return site, None, None


async def _get_json(client: httpx.AsyncClient, url: str) -> Any:
    try:
        response = await client.get(url, headers={"Accept": "application/json;odata=nometadata"})
    except httpx.RequestError as e:
        raise NetworkError(f"SharePoint request failed: {redact.redact_text(str(e))}") from e
    if response.status_code in (401, 403):
        raise AuthFailedError(f"SharePoint refused access ({response.status_code})")
    if response.status_code == 404:
        raise NotFoundError(f"SharePoint item not found: {redact.redact_text(url.split('?')[0])}")
    if response.status_code >= 500:
        raise NetworkError(f"SharePoint returned {response.status_code}")
    if response.status_code >= 400:
        raise NotFoundError(f"SharePoint returned {response.status_code}")
    try:
        return response.json()
    except json.JSONDecodeError as e:
        raise NetworkError("SharePoint returned non-JSON") from e


def _file_from(d: Mapping) -> SpItem:
    return SpItem(
        name=d.get("Name") or d.get("name") or "unnamed",
        server_relative_url=d.get("ServerRelativeUrl") or d.get("serverRelativeUrl") or "",
        kind="file",
        length=int(d["Length"]) if d.get("Length") is not None else d.get("size"),
        unique_id=(d.get("UniqueId") or d.get("id") or "").strip("{}") or None,
        etag=d.get("ETag") or d.get("eTag"),
        modified=d.get("TimeLastModified") or d.get("lastModifiedDateTime"),
    )


def _folder_from(d: Mapping) -> SpItem:
    return SpItem(
        name=d.get("Name") or d.get("name") or "unnamed",
        server_relative_url=d.get("ServerRelativeUrl") or d.get("serverRelativeUrl") or "",
        kind="folder",
        unique_id=(d.get("UniqueId") or d.get("id") or "").strip("{}") or None,
        etag=d.get("ETag") or d.get("eTag"),
        modified=d.get("TimeLastModified") or d.get("lastModifiedDateTime"),
    )


async def resolve(client: httpx.AsyncClient, url: str) -> SpTarget:
    """Turn a SharePoint / OneDrive URL into an ``SpTarget`` (file or folder)."""
    site, rel, unique_id = parse_url(url)
    host = urlsplit(site).hostname or ""
    if unique_id:
        data = await _get_json(
            client,
            f"{site}/_api/web/GetFileById('{unique_id}')?$select=Name,ServerRelativeUrl,Length,TimeLastModified,UniqueId,ETag",
        )
        item = _file_from(data)
        return SpTarget(site_url=site, host=host, item=item, is_folder=False)
    if rel:
        # Try as folder, then as file.
        enc = quote(rel, safe="/")
        try:
            data = await _get_json(
                client,
                f"{site}/_api/web/GetFolderByServerRelativeUrl('{enc}')"
                f"?$select=Name,ServerRelativeUrl,UniqueId,TimeLastModified,ItemCount",
            )
            item = _folder_from(data)
            return SpTarget(site_url=site, host=host, item=item, is_folder=True)
        except NotFoundError:
            data = await _get_json(
                client,
                f"{site}/_api/web/GetFileByServerRelativeUrl('{enc}')"
                f"?$select=Name,ServerRelativeUrl,Length,TimeLastModified,UniqueId,ETag",
            )
            item = _file_from(data)
            return SpTarget(site_url=site, host=host, item=item, is_folder=False)
    # Sharing-link fallback.
    share = "u!" + _b64url(url)
    data = await _get_json(client, f"{site}/_api/v2.0/shares/{share}/driveItem")
    folder = "folder" in data
    item = SpItem(
        name=data.get("name") or "unnamed",
        server_relative_url=data.get("parentReference", {}).get("path", "")
        + "/"
        + data.get("name", ""),
        kind="folder" if folder else "file",
        length=(data.get("size") if not folder else None),
        unique_id=data.get("id"),
        etag=data.get("eTag"),
        modified=data.get("lastModifiedDateTime"),
    )
    return SpTarget(site_url=site, host=host, item=item, is_folder=folder)


async def list_folder(client: httpx.AsyncClient, site: str, folder: SpItem) -> SpItem:
    """Fill ``folder.children`` (one level). Call recursively for a tree."""
    enc = quote(folder.server_relative_url, safe="/")
    files: list[SpItem] = []
    url = (
        f"{site}/_api/web/GetFolderByServerRelativeUrl('{enc}')/Files"
        f"?$select=Name,ServerRelativeUrl,Length,TimeLastModified,UniqueId,ETag"
    )
    while url:
        data = await _get_json(client, url)
        files.extend(_file_from(d) for d in data.get("value", data.get("d", {}).get("results", [])))
        url = data.get("@odata.nextLink") or data.get("odata.nextLink")
    folders: list[SpItem] = []
    url = (
        f"{site}/_api/web/GetFolderByServerRelativeUrl('{enc}')/Folders"
        f"?$select=Name,ServerRelativeUrl,UniqueId,TimeLastModified"
    )
    while url:
        data = await _get_json(client, url)
        for d in data.get("value", data.get("d", {}).get("results", [])):
            name = d.get("Name") or ""
            if name in ("Forms",):  # SharePoint system folder
                continue
            folders.append(_folder_from(d))
        url = data.get("@odata.nextLink") or data.get("odata.nextLink")
    folder.children = folders + files
    return folder


async def walk(
    client: httpx.AsyncClient, site: str, folder: SpItem
) -> AsyncIterator[tuple[str, SpItem]]:
    """Yield ``(relative_path, item)`` for every file under ``folder``."""
    await list_folder(client, site, folder)
    for child in folder.children:
        if child.kind == "folder":
            async for rel, item in walk(client, site, child):
                yield f"{child.name}/{rel}", item
        else:
            yield child.name, child


def download_url(site: str, item: SpItem) -> str:
    if item.unique_id and GUID.match(item.unique_id.strip("{}")):
        return f"{site}/_api/web/GetFileById('{item.unique_id.strip('{}')}')/$value"
    enc = quote(item.server_relative_url, safe="/")
    return f"{site}/_api/web/GetFileByServerRelativeUrl('{enc}')/$value"
