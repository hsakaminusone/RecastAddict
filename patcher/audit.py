"""Dangling-reference audit: every type referenced by surviving code that
resolves to no file in the tree and is not a framework class. That set is
exactly what the shim layer must cover.

Run:  python3 -m patcher audit
"""

from __future__ import annotations

import re
from pathlib import Path

from patcher import config

TYPE_RE = re.compile(rb"L(?:[A-Za-z][A-Za-z0-9_$]*/)+[A-Za-z0-9_$]*;")
FRAMEWORK = (
    "Landroid/",
    "Landroidx/",
    "Ldalvik/",
    "Ljava/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/xmlpull/",
    "Ljavax/",
    "Lorg/json/simple/",
    "Ljunit/",
    "Lsun/",
    "Llibcore/",
    "Lcom/android/",
    # Kept Play-services/Firebase sub-trees plus the app's own code. Never
    # allowlist a deleted tree here: gms/ads and gms/ump are deleted, so only
    # the preserved gms/auth sub-tree is listed (cf. config.KEEP_TREES).
    "Lcom/google/android/gms/auth/",
    "Lcom/google/firebase/messaging/",
    "Lcom/google/firebase/components/",
    "Lcom/google/firebase/common/",
    "Lcom/google/firebase/iid/",
    "Lcom/google/firebase/installations/",
    "Lcom/google/firebase/provider/",
    "Lcom/google/api/",
    "Lcom/google/common/",
    "Lcom/bambuna/",
)
# namespaces our patches delete -- references to these need a shim.
# Single source of truth: config.SHIM_NAMESPACES.
DELETED_PREFIXES = tuple("L" + ns + "/" for ns in config.SHIM_NAMESPACES)
# the shadow sub-tree is deliberately kept, so it is never "deleted"
KEPT_PREFIXES = ("Lcom/applovin/shadow/",)


def present_types(app_src: Path) -> set[str]:
    out: set[str] = set()
    for root in sorted(app_src.glob("smali*")):
        if not root.is_dir():
            continue
        for f in root.rglob("*.smali"):
            out.add(config.descriptor_for(root, f))
    return out


def run(app_src: Path | None = None) -> dict:
    app_src = Path(app_src or config.APP_SRC)
    present = present_types(app_src)
    # references made BY each file, so we can attribute a dangling ref to its user
    per_file: dict[Path, set[str]] = {}
    for root in sorted(app_src.glob("smali*")):
        if not root.is_dir():
            continue
        for f in sorted(root.rglob("*.smali")):
            data = f.read_bytes()
            # Our own shims reference each other; never count them as users.
            if b"recast-shim" in data[:400]:
                continue
            per_file[f] = {m.group(0).decode() for m in TYPE_RE.finditer(data)}

    dangling: dict[str, list[str]] = {}
    for f, refs in per_file.items():
        for r in refs:
            if r in present:
                continue
            # Deleted namespaces take precedence over the FRAMEWORK allowlist.
            if r.startswith(DELETED_PREFIXES) and not r.startswith(KEPT_PREFIXES):
                dangling.setdefault(r, []).append(str(f.relative_to(app_src)))
                continue
            if r.startswith(FRAMEWORK) or r.startswith(KEPT_PREFIXES):
                continue
            dangling.setdefault(r, []).append(str(f.relative_to(app_src)))

    needs_shim = {t: u for t, u in dangling.items() if t.startswith(DELETED_PREFIXES)}
    other = {t: u for t, u in dangling.items() if not t.startswith(DELETED_PREFIXES)}
    return {
        "present": len(present),
        "needs_shim": needs_shim,
        "other_dangling": other,
        "shimmed_already": sorted(t for t in needs_shim if t in present),
    }


def report(app_src: Path | None = None) -> int:
    r = run(app_src)
    ns, other = r["needs_shim"], r["other_dangling"]
    print(f"classes present : {r['present']:,}")
    print(f"dangling refs in DELETED SDK namespaces (need a shim): {len(ns)}")
    print(f"dangling refs elsewhere (investigate)              : {len(other)}")
    if ns:
        print("\n  -- by namespace --")
        agg: dict[str, int] = {}
        for t in ns:
            parts = t[1:-1].split("/")
            agg["/".join(parts[:3])] = agg.get("/".join(parts[:3]), 0) + 1
        for k, v in sorted(agg.items(), key=lambda x: -x[1]):
            print(f"    {k:38s} {v:4d}")
        print("\n  -- all types --")
        for t in sorted(ns):
            users = ns[t]
            print(f"    {t}   <- {len(users)} file(s) e.g. {users[0]}")
    if other:
        print("\n  -- OTHER dangling (not in a deleted namespace) --")
        for t in sorted(other)[:40]:
            print(f"    {t}   <- {other[t][0]}")
        if len(other) > 40:
            print(f"    ... {len(other) - 40} more")
    return 0
