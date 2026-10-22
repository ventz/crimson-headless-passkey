"""Map untrusted remote names (SharePoint/OneDrive) to paths that stay inside --out.

The names come from a server, so they are hostile input: ``..``, absolute
paths, Windows drives and separators, NUL and control characters, reserved
device names, overlong components, Unicode look-alikes and pre-planted
symlinks must never let a download (its ``.part`` file included) land outside
the output directory.

Defense in depth, in ``safe_target``:

1. Each component is validated on its own (both ``/`` and ``\\`` are treated as
   separators for rejection: backslashes are refused so a Windows-style name
   cannot smuggle a ``..``).
2. The joined path is ``resolve()``d, which follows any symlink already on disk,
   and must satisfy ``is_relative_to(out_dir.resolve())``.
3. ``open_for_write`` re-checks immediately before opening, refuses to follow a
   symlink at the final component (``O_NOFOLLOW``) and creates new files
   exclusively, so a symlink raced into place after the check still cannot
   redirect the write.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from pathlib import Path

from .errors import LoginPasskeyError

PART_SUFFIX = ".part"
MAX_COMPONENT_BYTES = 255 - len(PART_SUFFIX)  # room for ".part" on any filesystem
MAX_PATH_BYTES = 1024

WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
    | {f"COM{c}" for c in "\u00b9\u00b2\u00b3"}
    | {f"LPT{c}" for c in "\u00b9\u00b2\u00b3"}
)
# Characters with no business in a file name: C0/C1 controls, DEL, and Unicode
# format/bidi controls (U+202E RIGHT-TO-LEFT OVERRIDE can disguise "exe.txt").
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_FORBIDDEN = set('<>:"|?*')


class UnsafePathError(LoginPasskeyError):
    """A remote name would resolve outside the output directory, or is not a usable name."""


def check_component(name: str) -> str:
    """Validate one path component. Returns it NFC-normalized, or raises UnsafePathError."""
    if not isinstance(name, str):
        raise UnsafePathError(f"not a string: {type(name).__name__}")
    normalized = unicodedata.normalize("NFC", name)
    if normalized != unicodedata.normalize("NFKC", normalized) and _dot_lookalike(normalized):
        raise UnsafePathError(f"name uses look-alike dot characters: {name!r}")
    if _CONTROL.search(normalized):
        raise UnsafePathError(f"name contains control characters: {name!r}")
    if normalized == "" or normalized.strip() == "":
        raise UnsafePathError("empty or blank name")
    if set(normalized) <= {"."}:
        raise UnsafePathError(f"name is only dots: {name!r}")
    if "/" in normalized or "\\" in normalized:
        raise UnsafePathError(f"name contains a path separator: {name!r}")
    if any(c in _FORBIDDEN for c in normalized):
        raise UnsafePathError(f"name contains a reserved character: {name!r}")
    if normalized.endswith((" ", ".")):
        # Windows silently strips these, so "x." and "x" would collide.
        raise UnsafePathError(f"name ends with a space or dot: {name!r}")
    stem = normalized.split(".", 1)[0].rstrip(" ").upper()
    if stem in WINDOWS_RESERVED:
        raise UnsafePathError(f"reserved device name: {name!r}")
    if len(normalized.encode("utf-8")) > MAX_COMPONENT_BYTES:
        raise UnsafePathError(f"name is longer than {MAX_COMPONENT_BYTES} bytes")
    return normalized


def _dot_lookalike(name: str) -> bool:
    """True if compatibility normalization turns the name into dots or adds a separator."""
    compat = unicodedata.normalize("NFKC", name)
    return set(compat) <= {"."} or "/" in compat or "\\" in compat or ".." in compat


def split_remote(rel: str) -> list[str]:
    """Split a remote relative path on ``/``.

    Backslashes are rejected outright so a Windows-style name cannot smuggle
    ``..`` past a forward-slash-only split, and so a tree written on macOS or
    Linux stays portable. Empty parts (a leading separator = absolute path, or
    ``a//b``) are rejected rather than silently dropped.
    """
    if not isinstance(rel, str):
        raise UnsafePathError("remote path is not a string")
    if "\x00" in rel:
        raise UnsafePathError("remote path contains NUL")
    if "\\" in rel:
        raise UnsafePathError(f"remote path contains a backslash: {rel!r}")
    if len(rel.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES:
        raise UnsafePathError(f"remote path is longer than {MAX_PATH_BYTES} bytes")
    parts = rel.split("/")
    if any(p == "" for p in parts):
        raise UnsafePathError(f"absolute or malformed remote path: {rel!r}")
    return parts


def safe_target(out_dir: Path, rel: str) -> Path:
    """The resolved local path for remote relative path ``rel``, guaranteed inside ``out_dir``.

    Raises UnsafePathError for any name that is invalid or would escape.
    """
    base = Path(out_dir).resolve()
    parts = [check_component(p) for p in split_remote(rel)]
    candidate = base.joinpath(*parts)
    resolved = candidate.resolve()  # follows symlinks already present under out_dir
    ensure_inside(base, resolved)
    if resolved == base:
        raise UnsafePathError(f"remote path resolves to the output directory itself: {rel!r}")
    return resolved


def part_path(target: Path) -> Path:
    return target.with_name(target.name + PART_SUFFIX)


def ensure_inside(base: Path, path: Path) -> None:
    base = Path(base).resolve()
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(base):
        raise UnsafePathError(f"{path} resolves outside {base}")


def make_parents(base: Path, target: Path) -> None:
    """Create ``target``'s parent directories, refusing to walk through a symlink."""
    base = Path(base).resolve()
    ensure_inside(base, target)
    current = base
    for part in target.parent.relative_to(base).parts:
        current = current / part
        if current.is_symlink():
            raise UnsafePathError(f"{current} is a symlink; refusing to write through it")
        if current.exists() and not current.is_dir():
            raise UnsafePathError(f"{current} exists and is not a directory")
        current.mkdir(mode=0o700, exist_ok=True)
        ensure_inside(base, current)


def open_for_write(base: Path, path: Path, *, append: bool = False) -> int:
    """Open ``path`` (a target or its .part) for writing, re-checking containment first.

    Returns a raw file descriptor. Never follows a symlink at the final
    component; a fresh file is created exclusively. On resume-append the open
    file is checked: regular file, nlink==1, owned by the current user.
    """
    ensure_inside(base, path)
    if path.is_symlink():
        raise UnsafePathError(f"{path} is a symlink; refusing to write through it")
    ensure_inside(base, path.parent)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if append and path.exists():
        flags = os.O_WRONLY | os.O_APPEND | nofollow
        fd = os.open(path, flags, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(f"{path} is not a regular file")
            if st.st_nlink != 1:
                raise UnsafePathError(f"{path} has multiple hard links; refusing to append")
            if os.name == "posix" and st.st_uid != os.getuid():
                raise UnsafePathError(f"{path} is not owned by the current user")
        except Exception:
            os.close(fd)
            raise
        return fd
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
    if path.exists():
        path.unlink()  # a stale .part we will not resume
    return os.open(path, flags, 0o600)


def finalize(base: Path, part: Path, target: Path) -> None:
    """Atomically move a finished .part into place, both ends re-checked."""
    ensure_inside(base, part)
    ensure_inside(base, target)
    if target.is_symlink():
        raise UnsafePathError(f"{target} is a symlink; refusing to replace it")
    os.replace(part, target)
