"""Tolerant line scanner over smali files.

Only the constructs the patcher edits are parsed: ``.method``..``.end method``
blocks and, for the security_shrink module, ``const-string``/``HashSet.add``
pairs inside ``<clinit>``. Everything else is passed through as opaque bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from patcher.smali.span import SmaliMethodSpan, find_method_spans


class SmaliFile:
    """Read-only view of a smali file, addressed by byte span."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._data = self.path.read_bytes()
        self._spans = find_method_spans(self._data, self.path)

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def spans(self) -> list[SmaliMethodSpan]:
        return self._spans

    def find(
        self, name: str, descriptor: str, flags: tuple[str, ...] = ()
    ) -> SmaliMethodSpan | None:
        """Locate a method by name+descriptor (and optionally access flags)."""
        hits = [
            s
            for s in self._spans
            if s.name == name
            and s.descriptor == descriptor
            and (not flags or set(flags) <= set(s.access_flags))
        ]
        if len(hits) > 1:
            raise ValueError(
                f"{self.path}: {len(hits)} methods match {name}{descriptor} "
                f"with flags {flags}; descriptor is ambiguous under R8 overloading"
            )
        return hits[0] if hits else None

    def method_count(self) -> int:
        return len(self._spans)


def iter_smali_files(roots: list[Path]) -> Iterator[Path]:
    """Yield every .smali file across the given dex roots, in stable order."""
    for raw_root in roots:
        root = Path(raw_root)
        if not root.is_dir():
            continue
        yield from sorted(root.rglob("*.smali"))
