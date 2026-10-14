"""Byte-span addressing for smali methods.

The patcher never reserialises an smali file. It locates a method's byte span
and edits only the region between the ``.method`` header and ``.end method``.
This keeps untouched files byte-identical, which the whole plan rests on.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SmaliMethodSpan:
    """A located method, addressed by byte offsets into its file."""

    path: Path
    start: int  # offset of the ".method" line
    body_start: int  # offset just past the ".method" line (incl. newline)
    body_end: int  # offset of the ".end method" line
    end: int  # offset just past ".end method"
    header: bytes  # the .method line, verbatim
    name: str
    descriptor: str
    access_flags: tuple[str, ...]

    def body(self, data: bytes) -> bytes:
        return data[self.body_start : self.body_end]


def parse_method_line(line: bytes) -> tuple[str, str, tuple[str, ...]] | None:
    """Parse a ``.method`` line into (name, descriptor, access_flags)."""
    if not line.startswith(b".method"):
        return None
    # ".method public static f()Z" -> flags (public, static), name f, descr ()Z.
    # The name+descriptor is the LAST token; every preceding token is a flag.
    tokens = line[len(b".method") :].split()
    if not tokens:
        return None
    name_desc = tokens[-1]
    flags = tuple(t.decode() for t in tokens[:-1])
    op = name_desc.index(b"(")
    name = name_desc[:op].decode()
    descriptor = name_desc[op:].decode()
    return name, descriptor, flags


def find_method_spans(data: bytes, path: Path) -> list[SmaliMethodSpan]:
    """Locate every method in an smali file by byte offset.

    Scans lines only. A method block runs from a line starting ``.method`` to
    the next line that is exactly ``.end method``. Annotation lines inside the
    body (``.end annotation``, ``.end param``) do not terminate the block.
    """
    spans: list[SmaliMethodSpan] = []
    n = len(data)
    line_start = 0
    while line_start <= n:
        nl = data.find(b"\n", line_start)
        line_end = nl if nl != -1 else n
        line = data[line_start:line_end]
        if line.startswith(b".method"):
            parsed = parse_method_line(line)
            # find the terminating ".end method"
            # NOTE: the scan below must NOT reuse `line`/`line_end`. They hold
            # the ".method" line, which is what header/body_start are derived
            # from; clobbering them made every span's header become
            # ".end method" and body_start point past the method.
            cur = line_end + 1 if nl != -1 else n
            end_line_start = -1
            while cur <= n:
                nxt = data.find(b"\n", cur)
                sub_end = nxt if nxt != -1 else n
                sub_line = data[cur:sub_end].strip()
                if sub_line == b".end method":
                    end_line_start = cur
                    break
                if nxt == -1:
                    break
                cur = nxt + 1
            if end_line_start == -1:
                raise ValueError(f"{path}: unterminated method at offset {line_start}")
            end_nl = data.find(b"\n", end_line_start)
            end = end_nl + 1 if end_nl != -1 else n
            if parsed:
                name, descriptor, flags = parsed
                spans.append(
                    SmaliMethodSpan(
                        path=path,
                        start=line_start,
                        body_start=line_end + 1 if nl != -1 else n,
                        body_end=end_line_start,
                        end=end,
                        header=line,
                        name=name,
                        descriptor=descriptor,
                        access_flags=flags,
                    )
                )
            line_start = end
            continue
        if nl == -1:
            break
        line_start = nl + 1
    return spans


def register_decl(body: bytes) -> tuple[str, int] | None:
    """Return ('locals'|'registers', count) if the body opens with a register decl."""
    for raw in body.split(b"\n", 4)[:4]:
        line = raw.strip()
        if line.startswith(b".locals"):
            return "locals", int(line.split()[1])
        if line.startswith(b".registers"):
            return "registers", int(line.split()[1])
        if line.startswith(b"#") or not line:
            continue
        return None
    return None


def serialize(data: bytes, spans: list[SmaliMethodSpan]) -> bytes:
    """Rebuild a file from its spans.

    Re-derives newline placement and the ``.end method`` line for each method,
    so this is not the identity function: it fails if any span boundary is
    off by one or if a ``.end annotation`` was mistaken for ``.end method``.
    """
    out = bytearray()
    cursor = 0
    for s in spans:
        out += data[cursor : s.start]
        out += s.header
        out += b"\n"
        out += s.body(data)
        # the whole ".end method" line, verbatim (incl. its newline convention)
        out += data[s.body_end : s.end]
        cursor = s.end
    out += data[cursor:]
    return bytes(out)
