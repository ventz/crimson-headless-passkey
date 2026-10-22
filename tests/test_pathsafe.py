"""A streamed .part or final file must never escape --out.

Covers the cases the reviewer asked for: ``..``, absolute paths, Windows
drives and separators, NUL/controls, only-dots, reserved names, overlong
names, Unicode tricks and pre-planted symlinks. Every path (``.part``
included) goes through ``safe_target`` + ``ensure_inside`` + ``open_for_write``.
"""

from __future__ import annotations

import os

import pytest

from crimson_headless_passkey import pathsafe
from crimson_headless_passkey.pathsafe import UnsafePathError

BAD_NAMES = [
    "..",
    "../x",
    "../../x",
    "/etc/x",
    "/etc/passwd",
    "C:\\x",
    "C:/Windows/x",
    "..\\..\\x",
    "a\\..\\b",
    "a/../../b",
    "foo/../../../etc/passwd",
    "a\x00b",
    "a\nb",
    "a\tb",
    "a\x1fb",
    ".",
    "...",
    "....",
    " ",
    "  ",
    "CON",
    "con",
    "CON.txt",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "LPT9",
    "file.",
    "file ",
    "a:b",
    "a|b",
    "a*b",
    "a?b",
    "a<b",
    "a>b",
    'a"b',
    "\u202eexe.txt",  # right-to-left override
    "\ufeffx",  # BOM
    "\u200bx",  # zero-width space
]


@pytest.mark.parametrize("name", BAD_NAMES)
def test_bad_remote_name_is_rejected(tmp_path, name):
    with pytest.raises(UnsafePathError):
        pathsafe.safe_target(tmp_path, name)


def test_absolute_and_mixed_separators_rejected(tmp_path):
    for name in ("/etc/x", "\\Windows\\x", "a\\b/c", "a/b\\c"):
        with pytest.raises(UnsafePathError):
            pathsafe.safe_target(tmp_path, name)


def test_overlong_component_rejected(tmp_path):
    name = "a" * 300
    with pytest.raises(UnsafePathError, match="longer"):
        pathsafe.safe_target(tmp_path, name)


def test_unicode_nfc_accepted_and_contained(tmp_path):
    # café in NFD (e + combining acute) normalizes to NFC and stays inside.
    nfd = "cafe\u0301.txt"
    target = pathsafe.safe_target(tmp_path, nfd)
    assert target.is_relative_to(tmp_path.resolve())
    assert target.name == "caf\u00e9.txt"


def test_good_nested_name(tmp_path):
    target = pathsafe.safe_target(tmp_path, "Folder/Sub/file.pdf")
    assert target == (tmp_path / "Folder" / "Sub" / "file.pdf").resolve()
    assert target.is_relative_to(tmp_path.resolve())


def test_symlink_in_out_dir_cannot_escape(tmp_path):
    outside = tmp_path.parent / "outside-escape-target"
    outside.mkdir()
    plant = tmp_path / "link"
    plant.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        pathsafe.safe_target(tmp_path, "link/secret.txt")


def test_symlink_at_final_component_refused_by_open(tmp_path):
    outside = tmp_path.parent / "outside-file"
    outside.write_text("nope")
    target = tmp_path / "file.txt"
    target.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        pathsafe.open_for_write(tmp_path.resolve(), target)


def test_part_and_final_stay_inside(tmp_path):
    target = pathsafe.safe_target(tmp_path, "docs/a.bin")
    part = pathsafe.part_path(target)
    pathsafe.ensure_inside(tmp_path.resolve(), part)
    pathsafe.make_parents(tmp_path.resolve(), target)
    fd = pathsafe.open_for_write(tmp_path.resolve(), part)
    os.write(fd, b"hello")
    os.close(fd)
    pathsafe.finalize(tmp_path.resolve(), part, target)
    assert target.read_bytes() == b"hello"
    assert not part.exists()
    assert target.is_relative_to(tmp_path.resolve())


def test_resolve_then_is_relative_to_is_the_guard(tmp_path):
    """Document the exact check the reviewer asked for."""
    base = tmp_path.resolve()
    target = pathsafe.safe_target(tmp_path, "ok/file.txt")
    assert target.resolve().is_relative_to(base)
    # A crafted Path that joins .. after validation would still fail ensure_inside:
    sneaky = tmp_path / "ok" / ".." / ".." / "escape.txt"
    with pytest.raises(UnsafePathError):
        pathsafe.ensure_inside(base, sneaky)
