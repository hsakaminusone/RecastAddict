"""Ground-truth shape capture for types our patches delete.

Shapes (.super/.implements/is-interface) are read from the ORIGINAL source
APK, so the map is complete regardless of which pass deleted what. Cached
under anchors/; safe to delete, regenerates on demand.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from patcher import config

if TYPE_CHECKING:
    from patcher.patches.base import Context

SHAPE_FILE = "deleted_sdk_classes.json"

_CLASS_RE = re.compile(
    rb"^\.class\s+(?P<flags>[a-z ]*?)\s*(?P<name>L[A-Za-z0-9/$_]+;)", re.MULTILINE
)
_SUPER_RE = re.compile(rb"^\.super\s+(?P<sup>L[A-Za-z0-9/$_]+;)", re.MULTILINE)
_IMPL_RE = re.compile(rb"^\.implements\s+(?P<impl>L[A-Za-z0-9/$_]+;)", re.MULTILINE)


def is_interface(smali_bytes: bytes) -> bool:
    """True when the .class header carries the `interface` access flag."""
    m = _CLASS_RE.search(smali_bytes)
    if not m:
        return False
    return b"interface" in m.group("flags")


def shape_of(smali_bytes: bytes) -> dict:
    """The class's identity: super, interfaces, and whether it is an interface."""
    sup = _SUPER_RE.search(smali_bytes)
    return {
        "super": sup.group("sup").decode() if sup else "Ljava/lang/Object;",
        "implements": [i.group("impl").decode() for i in _IMPL_RE.finditer(smali_bytes)],
        "is_interface": is_interface(smali_bytes),
    }


def collect_from_decode(decode_root: Path) -> dict[str, dict]:
    """Every shim-namespace type in a decoded tree, with its real shape.

    Skips our own generated shims (recast-shim marker).
    """
    roots = [p for p in sorted(decode_root.glob("smali*")) if p.is_dir()]
    prefixes = tuple("L" + ns + "/" for ns in config.SHIM_NAMESPACES)
    out: dict[str, dict] = {}
    for root in roots:
        for f in sorted(root.rglob("*.smali")):
            # collision-aware: ej.1.smali declares Lej; (cf. descriptor_for)
            desc = config.descriptor_for(root, f)
            if not desc.startswith(prefixes):
                continue
            try:
                data = f.read_bytes()
            except OSError:
                continue
            if b"recast-shim" in data[:400]:
                continue
            out[desc] = shape_of(data)
    return out


def capture(ctx: Context, needed: set[str] | None = None, verbose: bool = False) -> dict[str, dict]:
    """Capture shapes for SHIM_NAMESPACES, preferring the ORIGINAL source APK.

    Idempotent and cached under anchors/.
    """
    import subprocess  # nosec B404 -- PATH tools, never shell
    import tempfile

    cache = Path(ctx.anchors_dir) / SHAPE_FILE
    cached: dict[str, dict] = {}
    if cache.is_file():
        try:
            cached = json.loads(cache.read_text())
        except Exception:
            cached = {}

    # Entries missing any key are refilled from ground truth.
    def _complete(shape: dict) -> bool:
        return (
            isinstance(shape, dict)
            and "super" in shape
            and "implements" in shape
            and "is_interface" in shape
        )

    missing = set(needed or set()) - {d for d, s in cached.items() if _complete(s)}
    from_tree = collect_from_decode(ctx.app_src)
    filled_from_tree = {d: from_tree[d] for d in missing if d in from_tree}
    still_missing = missing - set(filled_from_tree)

    if still_missing and not ctx.offline:
        with tempfile.TemporaryDirectory(prefix="recast-shapes-") as tmp:
            r = subprocess.run(  # noqa: S603  # nosec B603 -- fixed apktool argv
                [config.APKTOOL, "d", "-f", "-q", str(config.source_apk()), "-o", tmp],
                capture_output=True,
                text=True,
            )
            if r.returncode:
                raise RuntimeError(f"shape capture decode failed: {r.stderr[-600:]}")
            truth = collect_from_decode(Path(tmp))
            # Merge the whole shim-namespace universe: the shim closure walks
            # supertypes nobody referenced directly.
            for d, shp in truth.items():
                filled_from_tree.setdefault(d, shp)
            if verbose:
                print(
                    f"  shapes: source-APK decode supplied "
                    f"{sum(1 for d in still_missing if d in truth)}/"
                    f"{len(still_missing)} missing types "
                    f"({len(truth)} cached total)"
                )

    src = {d: s for d, s in cached.items() if _complete(s)}
    src.update(filled_from_tree)
    if src and src != cached:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(src, indent=1, sort_keys=True))
    if verbose:
        print(f"  shapes: {len(src)} types on record")
    return src
