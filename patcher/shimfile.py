"""Identify files the patcher itself generated."""

from __future__ import annotations

from pathlib import Path


def our_shim(path: Path | str) -> bool:
    """True when a smali file is one of our generated shims.

    Every verify() that asserts an SDK tree is gone must use this, or it counts
    our own output as surviving SDK code and reports a false failure.
    """
    try:
        return b"recast-shim" in Path(path).read_bytes()[:400]
    except OSError:
        return False
