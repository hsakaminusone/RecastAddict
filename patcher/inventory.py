"""Census of the decoded tree. Everything here is measured, never assumed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .smali.reader import SmaliFile, iter_smali_files

AD_NS = ("applovin", "fyber", "inmobi", "pubmatic")
# Full-match pattern, no capture group: findall returns whole descriptors.
_TYPE_RE = re.compile(rb"Lcom/(?:applovin|fyber|inmobi|pubmatic)/[A-Za-z0-9/_$]+;")
_SHADOW_PREFIX = b"Lcom/applovin/shadow/"


@dataclass
class Census:
    smali_files: int = 0
    methods: int = 0
    per_root: dict[str, int] = field(default_factory=dict)
    sdk_tree_files: dict[str, int] = field(default_factory=dict)
    external_ref_files: dict[str, int] = field(default_factory=dict)
    set_s_types: int = 0
    set_s_by_sdk: dict[str, int] = field(default_factory=dict)
    class_for_name: int = 0
    load_library: dict[str, int] = field(default_factory=dict)
    telemetry_literals: dict[str, int] = field(default_factory=dict)
    asset_refs: dict[str, int] = field(default_factory=dict)
    shadow_okhttp_files: int = 0


def _dex_roots(app_src: Path) -> list[Path]:
    return [p for p in sorted(app_src.glob("smali*")) if p.is_dir()]


def _is_island(posix: str) -> bool:
    """True when a file lives inside a tree our patches delete."""
    return any(f"/{ns}/" in posix for ns in config.DELETED_SDK_TREES)


def _is_survivor(posix: str) -> bool:
    """True when a file's references count as survivor references: outside the
    deleted SDK islands and outside the kept shadow HTTP stack."""
    return "/com/applovin/shadow/" not in posix and not _is_island(posix)


def survivor_ad_refs(app_src: Path) -> set[bytes]:
    """Distinct ad-SDK types referenced by surviving code (Set S).

    Single source of truth: inventory, shrink, and the report all derive their
    Set S number from here, so the three can never diverge again. A reference
    counts only when it comes from a survivor -- files inside a deleted SDK
    island, inside com/applovin/shadow (the kept HTTP stack), or our own
    generated shims are not survivors.

    NOTE: patcher/audit.py deliberately uses a wider net (every referencing
    file including shadow) because the shim layer must cover each dangling
    reference no matter who holds it. That set answers "what must we shim";
    this set answers "how much ad surface do survivors still touch".
    """
    out: set[bytes] = set()
    for f in iter_smali_files(_dex_roots(Path(app_src))):
        posix = f.as_posix()
        if not _is_survivor(posix):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"recast-shim" in data[:400]:
            continue
        out |= set(_TYPE_RE.findall(data))
    return {t for t in out if not t.startswith(_SHADOW_PREFIX)}


def build(app_src: Path | None = None) -> Census:
    app_src = Path(app_src or config.APP_SRC)
    c = Census()
    files = list(iter_smali_files(_dex_roots(app_src)))
    c.smali_files = len(files)

    for root in _dex_roots(app_src):
        c.per_root[root.name] = sum(1 for f in files if f.is_relative_to(root))

    # Single pass: every file is read exactly once (plus the method-count
    # sample below). Set S accumulates inline under the same survivor rule.
    for ns in AD_NS:
        c.external_ref_files[ns] = 0
        c.sdk_tree_files[ns] = 0
    shadow = 0
    set_s: set[bytes] = set()
    for f in files:
        data = f.read_bytes()
        posix = f.as_posix()
        is_shadow = "/com/applovin/shadow/" in posix
        if is_shadow:
            shadow += 1
        for ns in AD_NS:
            if f"/com/{ns}/" in posix:
                c.sdk_tree_files[ns] += 1
        # reflection sites: counted for EVERY file, not just ad-referencing ones
        for lit in (b"Class;->forName(", b"Class;->loadClass("):
            c.class_for_name += data.count(lit)
        if _is_survivor(posix) and b"recast-shim" not in data[:400]:
            hits = _TYPE_RE.findall(data)
            set_s |= set(hits)
            seen_ns = {m.decode().split("/")[1] for m in hits}
            for ns in seen_ns:
                if ns in c.external_ref_files:
                    c.external_ref_files[ns] += 1
        for ep in config.BLOCKED_ENDPOINTS:
            n = data.count(ep.encode())
            if n:
                c.telemetry_literals[ep] = c.telemetry_literals.get(ep, 0) + n
        for m in re.finditer(rb"const-string [vp]\d+, \"([A-Za-z0-9_\-]{3,60})\"", data):
            if b"loadLibrary" in data[max(0, m.start() - 400) : m.start() + 400]:
                c.load_library[m.group(1).decode()] = c.load_library.get(m.group(1).decode(), 0) + 1
        for asset in [
            *config.FUNCTIONAL_ASSETS,
            "privacy_consent.html",
            "setup.css",
            "tutorial.css",
        ]:
            n = data.count(asset.encode())
            if n:
                c.asset_refs[asset] = c.asset_refs.get(asset, 0) + n

    c.shadow_okhttp_files = shadow
    # Same survivor rule as survivor_ad_refs() (_is_survivor + _TYPE_RE), so the
    # two can never diverge; no second tree walk to prove it.
    non_shadow = {t for t in set_s if not t.startswith(_SHADOW_PREFIX)}
    c.set_s_types = len(non_shadow)
    for ns in AD_NS:
        # exclude shadow sub-tree AND other SDK namespaces: com/applovin/mediation
        # adapters reference com/inmobi/, so a per-SDK count must be exclusive
        c.set_s_by_sdk[ns] = sum(1 for t in non_shadow if t.startswith(f"Lcom/{ns}/".encode()))

    # method count: measured on a sample and extrapolated (documented as an
    # estimate, not a census). The exact figure is in the round-trip test.
    sample = files[:2000]
    counted = sum(SmaliFile(f).method_count() for f in sample)
    c.methods = int(counted * len(files) / max(1, len(sample)))

    return c


def to_dict(c: Census) -> dict:
    return {
        "smali_files": c.smali_files,
        "methods": c.methods,
        "per_root": c.per_root,
        "sdk_tree_files": c.sdk_tree_files,
        "external_ref_files": c.external_ref_files,
        "set_s_types": c.set_s_types,
        "set_s_by_sdk": c.set_s_by_sdk,
        "shadow_okhttp_files": c.shadow_okhttp_files,
        "class_for_name_sites": c.class_for_name,
        "load_library": c.load_library,
        "telemetry_literals": c.telemetry_literals,
        "asset_refs": c.asset_refs,
    }
