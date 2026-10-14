"""Byte-span edits.

Every edit is a transaction on a byte span. Untouched files are never written,
so the whole-tree round-trip invariant is preserved by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from patcher.smali.reader import SmaliFile
from patcher.smali.span import SmaliMethodSpan


@dataclass
class Edit:
    """One journaled edit."""

    path: Path
    old_bytes: bytes
    new_bytes: bytes
    reason: str


def _stub_body(returns: str, value: int = 1) -> bytes:
    """A minimal body for a stubbed method, given its return descriptor.

    `value` is the constant returned for Z; some gates must stub to FALSE (e.g.
    y31.k() should return false to *hide* the premium upsell).
    """
    if returns == "V":
        return b"    .locals 0\n    return-void\n"
    if returns == "Z":
        return b"    .locals 1\n    const/4 v0, 0x%x\n    return v0\n" % value
    if returns.startswith(("L", "[")):
        # object / array -> null (the app's own "donated" path returns null)
        return b"    .locals 1\n    const/4 v0, 0x0\n    return-object v0\n"
    raise ValueError(f"unsupported return descriptor for stubbing: {returns!r}")


def is_stub(data: bytes, span: SmaliMethodSpan, returns: str, value: int = 1) -> bool:
    """True if the method body is already exactly this stub (idempotency)."""
    try:
        return span.body(data) == _stub_body(returns, value)
    except ValueError:
        return False


def stub_method(
    smali: SmaliFile, name: str, descriptor: str, *, reason: str, value: int = 1
) -> Edit | None:
    """Replace a method's body with a constant-return stub.

    Returns an Edit, or None if the method is already stubbed.
    Raises KeyError if the method is not found -- fail loud, never guess.
    """
    span = smali.find(name, descriptor)
    if span is None:
        raise KeyError(
            f"{smali.path}: method {name}{descriptor} not found; "
            f"anchor resolution must have been checked by preflight"
        )
    returns = descriptor[descriptor.index(")") + 1 :]
    if is_stub(smali.data, span, returns, value):
        return None
    new = smali.data[: span.body_start] + _stub_body(returns, value) + smali.data[span.body_end :]
    return Edit(path=smali.path, old_bytes=smali.data, new_bytes=new, reason=reason)


def _journal_key(app_src: Path, path: Path, idx: int) -> str:
    """A collision-free journal key.

    A basename is NOT enough: "a.smali" exists under ~10 different dex paths,
    so a basename key makes `revert` restore an arbitrary one.
    """
    try:
        rel = str(Path(path).resolve().relative_to(Path(app_src).resolve()))
    except ValueError:
        rel = Path(path).name
    safe = rel.replace("/", "__")
    return f"{idx:04d}_{safe}"


def apply_edits(
    edits: list[Edit], journal_dir: Path, module: str, app_src: Path | None = None
) -> list[Path]:
    """Write edits to disk, recording old bytes in the journal."""
    touched: list[Path] = []
    if app_src is None:
        from patcher import config  # avoid an import cycle at module load

        app_src = config.APP_SRC
    base = app_src
    for e in edits:
        if e.old_bytes == e.new_bytes:
            continue
        jdir = Path(journal_dir) / module
        jdir.mkdir(parents=True, exist_ok=True)
        idx = len(list(jdir.iterdir()))
        (jdir / _journal_key(base, e.path, idx)).write_bytes(e.old_bytes)
        e.path.write_bytes(e.new_bytes)
        touched.append(e.path)
    return touched
