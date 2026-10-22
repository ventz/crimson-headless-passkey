"""Download one file, or a SharePoint/OneDrive folder recursively, after sign-in.

Mechanism (see the design note):

1. ``signed_in(url)`` opens the link; the authenticator is already detached and
   the run lock released when it returns.
2. Cookies for the target host go into an in-memory ``httpx`` client.
3. SharePoint REST resolves the URL, lists folders and streams each file to
   ``name.part``, then renames. Resume uses ``Range`` when the server answers
   206; otherwise the .part is restarted. A non-secret
   ``DIR/.harvard-fetch.json`` records UniqueId / ETag / Length so a second
   run skips files that are already present.
4. Non-SharePoint URLs get a plain GET (or Playwright's download API when the
   response is a browser download).

PeopleSoft URLs are refused. SharePoint and OneDrive sites are the intended use.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import pathsafe, redact, session, sharepoint, storage
from .config import Settings, host_of, is_peoplesoft_url, validate_url
from .errors import (
    AuthFailedError,
    LoginPasskeyError,
    NetworkError,
    NotFoundError,
    RefusedURLError,
)
from .exitcodes import (
    STATUS_AUTH_FAILED,
    STATUS_NETWORK,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_PARTIAL,
)
from .pathsafe import UnsafePathError

MANIFEST_NAME = ".harvard-fetch.json"

SHAREPOINT_HOST_SUFFIXES = (
    ".sharepoint.com",
    ".sharepoint-df.com",
    "-my.sharepoint.com",
)
ONEDRIVE_HOST_SUFFIXES = (".onedrive.com", ".live.com")


def is_sharepoint_host(host: str) -> bool:
    """Exact parsed-hostname match: host is a SharePoint / OneDrive host."""
    host = (host or "").lower()
    if not host:
        return False
    if host in ("sharepoint.com", "onedrive.com", "live.com"):
        return True
    return any(host.endswith(s) for s in SHAREPOINT_HOST_SUFFIXES + ONEDRIVE_HOST_SUFFIXES)


def check_out_dir(out: Path) -> None:
    """Refuse an output directory others can write to."""
    import stat as _stat

    if not out.is_dir():
        raise RefusedURLError(f"{out} is not a directory")
    if os.name != "posix":
        return
    st = out.stat()
    if st.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
        raise RefusedURLError(
            f"{out} is writable by other users (mode {_stat.filemode(st.st_mode)}). "
            f"Fix with: chmod 700 {out}"
        )


_STATUS_CODE = {
    "ok": 0,
    "auth_failed": 1,
    "config": 2,
    "needs_human": 3,
    "network": 4,
    "not_found": 5,
    "partial": 6,
}
CHUNK = 64 * 1024
MAX_RETRIES = 4


@dataclass
class FileOutcome:
    rel: str
    status: str  # fetched, skipped, failed
    bytes: int = 0
    reason: str | None = None


@dataclass
class FetchReport:
    ok: bool
    status: str
    url: str
    out_dir: Path
    files: list[FileOutcome] = field(default_factory=list)
    fetched: int = 0
    skipped: int = 0
    failed: int = 0
    bytes: int = 0
    elapsed_s: float = 0.0
    reason: str | None = None

    def status_line(self) -> str:
        code = _STATUS_CODE.get(self.status, 2)
        return (
            f"crimson-headless-passkey: {self.status} code={code}"
            f" fetched={self.fetched} skipped={self.skipped} failed={self.failed}"
            f" bytes={_fmt_bytes(self.bytes)} {self.elapsed_s:.1f}s"
        )


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024**2:
        return f"{n / 1024:.1f}KB"
    if n < 1024**3:
        return f"{n / 1024**2:.1f}MB"
    return f"{n / 1024**3:.1f}GB"


def load_manifest(out_dir: Path) -> dict[str, Any]:
    path = out_dir / MANIFEST_NAME
    if not path.is_file():
        return {"version": 1, "files": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {"version": 1, "files": {}}
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        return {"version": 1, "files": {}}
    return data


def save_manifest(out_dir: Path, manifest: dict[str, Any]) -> None:
    # Non-secret: UniqueId, ETag, Length, mtime. Still owner-only out of habit.
    pathsafe.ensure_inside(out_dir.resolve(), (out_dir / MANIFEST_NAME).resolve())
    storage.write_private_json(out_dir / MANIFEST_NAME, manifest)


def should_skip(local: Path, entry: dict[str, Any] | None, item: sharepoint.SpItem) -> bool:
    if entry is None or not local.is_file():
        return False
    if local.is_symlink():
        return False
    size = local.stat().st_size
    if item.length is not None and size != item.length:
        return False
    if (
        item.etag
        and entry.get("etag") == item.etag
        and (item.length is None or size == item.length)
    ):
        return True
    if item.length is not None and size == item.length and entry.get("length") == item.length:
        if item.modified and entry.get("modified") == item.modified:
            return True
        if item.unique_id and entry.get("unique_id") == item.unique_id:
            return True
    return False


async def _stream_to(
    client: httpx.AsyncClient,
    url: str,
    base: Path,
    target: Path,
    *,
    resume: bool,
    expected: int | None,
) -> int:
    """Stream ``url`` into ``target`` via a ``.part`` file. Returns bytes written."""
    pathsafe.make_parents(base, target)
    part = pathsafe.part_path(target)
    pathsafe.ensure_inside(base, part)
    start = 0
    if resume and part.exists() and not part.is_symlink():
        start = part.stat().st_size
    headers = {"Range": f"bytes={start}-"} if start else {}
    try:
        async with client.stream("GET", url, headers=headers) as response:
            if response.status_code in (401, 403):
                raise AuthFailedError(f"download refused ({response.status_code})")
            if response.status_code == 404:
                raise NotFoundError("file not found")
            if response.status_code == 416:  # Range not satisfiable: restart
                start = 0
                part.unlink(missing_ok=True)
                return await _stream_to(client, url, base, target, resume=False, expected=expected)
            if start and response.status_code == 200:
                # Server ignored Range: restart cleanly.
                start = 0
                part.unlink(missing_ok=True)
            if response.status_code not in (200, 206):
                if response.status_code >= 500:
                    raise NetworkError(f"download returned {response.status_code}")
                raise NotFoundError(f"download returned {response.status_code}")
            append = start > 0 and response.status_code == 206
            fd = pathsafe.open_for_write(base, part, append=append)
            written = start
            try:
                with os.fdopen(fd, "wb") as f:
                    async for chunk in response.aiter_bytes(CHUNK):
                        f.write(chunk)
                        written += len(chunk)
                    f.flush()
                    os.fsync(f.fileno())
            except BaseException:
                # Leave the .part for resume; do not finalize.
                raise
    except httpx.RequestError as e:
        raise NetworkError(redact.redact_text(str(e))) from redact.scrubbed_exception(e)
    pathsafe.finalize(base, part, target)
    return written


async def _with_retries(coro_factory: Callable[[], Any], *, retries: int = MAX_RETRIES) -> Any:
    delay = 1.0
    last: Exception | None = None
    for attempt in range(retries):
        try:
            return await coro_factory()
        except NetworkError as e:
            last = e
            if attempt + 1 == retries:
                raise
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)
        except AuthFailedError:
            raise
    assert last is not None
    raise last


async def fetch(
    url: str,
    out_dir: Path | str,
    *,
    settings: Settings | None = None,
    recursive: bool = True,
    resume: bool = True,
    overwrite: bool = False,
    dry_run: bool = False,
    concurrency: int = 4,
    headless: bool = True,
    channel: str | None = None,
    timeout_s: float = 30,
    use_saved_state: bool = True,
    save_state: bool = False,
    on_status: Callable[[str], None] | None = None,
    cookies_out: Path | str | None = None,
    force_cookies: bool = False,
) -> FetchReport:
    """Sign in, then download ``url`` into ``out_dir``. See module docstring.

    The saved session is read (unless ``use_saved_state`` is False) but not
    written back unless ``save_state`` is True: a download job should not leave
    fresh site cookies behind by default.
    """
    with redact.active():
        started = time.monotonic()
        settings = settings or Settings.from_env()
        url = validate_url(url)
        if is_peoplesoft_url(url):
            raise RefusedURLError(
                "refusing to fetch PeopleSoft (Harvard HR/payroll). "
                "Use `crimson-headless-passkey login -v --headless --close --no-save-state` only."
            )
        out = Path(out_dir).expanduser().resolve()
        out.mkdir(mode=0o700, parents=True, exist_ok=True)
        check_out_dir(out)
        pathsafe.ensure_inside(out, out)  # establishes the resolve baseline
        note = on_status or (lambda _m: None)

        async with session.signed_in(
            url,
            settings,
            headless=headless,
            channel=channel,
            timeout_s=timeout_s,
            use_saved_state=use_saved_state,
            save_state=save_state,
        ) as signed:
            site_host = host_of(signed.page.url) or host_of(url)
            client = await session.http_client(signed, site_host, settings=settings)
            try:
                report = await _fetch_with_client(
                    client,
                    signed,
                    url,
                    out,
                    recursive=recursive,
                    resume=resume,
                    overwrite=overwrite,
                    dry_run=dry_run,
                    concurrency=concurrency,
                    note=note,
                    started=started,
                )
                if cookies_out and report.ok:
                    cookies = await signed.cookies_for(signed.page.url)
                    session.save_cookies(
                        cookies,
                        Path(cookies_out),
                        site=signed.page.url,
                        settings=settings,
                        force=force_cookies,
                    )
                return report
            finally:
                await client.aclose()


async def _fetch_with_client(
    client: httpx.AsyncClient,
    signed: session.SignedIn,
    url: str,
    out: Path,
    *,
    recursive: bool,
    resume: bool,
    overwrite: bool,
    dry_run: bool,
    concurrency: int,
    note: Callable[[str], None],
    started: float,
) -> FetchReport:
    host = urlsplit(url).hostname or ""
    settled = host_of(signed.page.url)
    is_sp = is_sharepoint_host(host) or is_sharepoint_host(settled)
    if is_sp and settled and is_sharepoint_host(settled):
        url = signed.page.url  # prefer the post-redirect URL for resolution

    report = FetchReport(ok=True, status=STATUS_OK, url=url, out_dir=out)
    manifest = load_manifest(out)

    try:
        if is_sp:
            await _fetch_sharepoint(
                client,
                url,
                out,
                report,
                manifest,
                recursive=recursive,
                resume=resume,
                overwrite=overwrite,
                dry_run=dry_run,
                concurrency=concurrency,
                note=note,
            )
        else:
            await _fetch_plain(
                client,
                signed,
                url,
                out,
                report,
                manifest,
                resume=resume,
                overwrite=overwrite,
                dry_run=dry_run,
                note=note,
            )
    except NotFoundError as e:
        report.ok, report.status, report.reason = False, STATUS_NOT_FOUND, str(e)
    except AuthFailedError as e:
        report.ok, report.status, report.reason = False, STATUS_AUTH_FAILED, str(e)
    except (NetworkError, httpx.HTTPError) as e:
        report.ok, report.status, report.reason = False, STATUS_NETWORK, redact.redact_text(str(e))
    except UnsafePathError as e:
        report.ok, report.status, report.reason = False, "config", str(e)
    except LoginPasskeyError as e:
        report.ok, report.status, report.reason = False, getattr(e, "status", "config"), str(e)

    if report.failed and report.status == STATUS_OK:
        report.ok, report.status = False, STATUS_PARTIAL
    if not dry_run:
        save_manifest(out, manifest)
    report.elapsed_s = time.monotonic() - started
    return report


async def _fetch_sharepoint(
    client, url, out, report, manifest, *, recursive, resume, overwrite, dry_run, concurrency, note
):
    target = await sharepoint.resolve(client, url)
    if target.is_folder:
        if not recursive:
            # Download only the files in this folder, no subfolders.
            await sharepoint.list_folder(client, target.site_url, target.item)
            items = [(child.name, child) for child in target.item.children if child.kind == "file"]
        else:
            items = [pair async for pair in sharepoint.walk(client, target.site_url, target.item)]
    else:
        items = [(target.item.name, target.item)]

    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(rel: str, item: sharepoint.SpItem) -> None:
        async with sem:
            await _one_file(
                client,
                target.site_url,
                sharepoint.download_url(target.site_url, item),
                rel,
                item,
                out,
                report,
                manifest,
                resume=resume,
                overwrite=overwrite,
                dry_run=dry_run,
                note=note,
            )

    await asyncio.gather(*(one(rel, item) for rel, item in items))


async def _one_file(
    client, site, dl_url, rel, item, out, report, manifest, *, resume, overwrite, dry_run, note
):
    try:
        target = pathsafe.safe_target(out, rel)
    except UnsafePathError as e:
        report.files.append(FileOutcome(rel=rel, status="failed", reason=str(e)))
        report.failed += 1
        return
    entry = manifest["files"].get(rel)
    if not overwrite and should_skip(target, entry, item):
        report.files.append(FileOutcome(rel=rel, status="skipped", bytes=target.stat().st_size))
        report.skipped += 1
        note(f"skip {rel}")
        return
    if dry_run:
        report.files.append(FileOutcome(rel=rel, status="fetched", bytes=item.length or 0))
        report.fetched += 1
        note(f"would fetch {rel}")
        return
    try:
        nbytes = await _with_retries(
            lambda: _stream_to(client, dl_url, out, target, resume=resume, expected=item.length)
        )
    except (AuthFailedError, NetworkError, NotFoundError) as e:
        report.files.append(FileOutcome(rel=rel, status="failed", reason=str(e)))
        report.failed += 1
        note(f"fail {rel}: {e}")
        return
    report.files.append(FileOutcome(rel=rel, status="fetched", bytes=nbytes))
    report.fetched += 1
    report.bytes += nbytes
    manifest["files"][rel] = {
        "unique_id": item.unique_id,
        "etag": item.etag,
        "length": item.length if item.length is not None else nbytes,
        "modified": item.modified,
    }
    note(f"fetched {rel} ({_fmt_bytes(nbytes)})")


async def _fetch_plain(
    client, signed, url, out, report, manifest, *, resume, overwrite, dry_run, note
):
    name = Path(urlsplit(url).path).name or "download"
    try:
        target = pathsafe.safe_target(out, name)
    except UnsafePathError as e:
        raise RefusedURLError(str(e)) from e
    if not overwrite and target.is_file() and not target.is_symlink():
        report.files.append(FileOutcome(rel=name, status="skipped", bytes=target.stat().st_size))
        report.skipped += 1
        return
    if dry_run:
        report.files.append(FileOutcome(rel=name, status="fetched"))
        report.fetched += 1
        return
    try:
        nbytes = await _stream_to(client, url, out, target, resume=resume, expected=None)
    except NotFoundError:
        # Some sites only serve the file as a browser download. Do not fall back
        # after NetworkError / AuthFailedError (the guard already refused the hop).
        nbytes = await _playwright_download(signed, url, out, target)
    report.files.append(FileOutcome(rel=name, status="fetched", bytes=nbytes))
    report.fetched += 1
    report.bytes += nbytes
    manifest["files"][name] = {"length": nbytes}


async def _playwright_download(signed, url, out, target) -> int:
    """Save a browser download through a private temp dir, then pathsafe."""
    import tempfile

    pathsafe.make_parents(out, target)
    tmp_dir = Path(tempfile.mkdtemp(prefix=".harvard-fetch-", dir=out))
    try:
        os.chmod(tmp_dir, 0o700)
        async with signed.page.expect_download(timeout=60_000) as pending:
            await signed.page.goto(url)
        download = await pending.value
        tmp_file = tmp_dir / "download.bin"
        await download.save_as(tmp_file)
        pathsafe.ensure_inside(out, tmp_file)
        part = pathsafe.part_path(target)
        fd = pathsafe.open_for_write(out, part, append=False)
        try:
            with os.fdopen(fd, "wb") as dest, open(tmp_file, "rb") as src:
                while True:
                    chunk = src.read(CHUNK)
                    if not chunk:
                        break
                    dest.write(chunk)
                dest.flush()
                os.fsync(dest.fileno())
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        pathsafe.finalize(out, part, target)
        return target.stat().st_size
    finally:
        for child in tmp_dir.iterdir():
            child.unlink(missing_ok=True)
        tmp_dir.rmdir()


def fetch_sync(url: str, out_dir: Path | str, **kwargs: Any) -> FetchReport:
    """Synchronous wrapper around ``fetch`` for scripts that are not async."""
    return asyncio.run(fetch(url, out_dir, **kwargs))
