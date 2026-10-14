"""Preflight: resolve all anchors and clear the risk audits before any mutation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from patcher import config
from patcher.patches import order_patches
from patcher.patches.base import AnchorError, Context


@dataclass
class Audit:
    id: str
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class PreflightResult:
    audits: list[Audit] = field(default_factory=list)

    @property
    def failures(self) -> list[Audit]:
        return [a for a in self.audits if not a.ok]

    def summary(self) -> str:
        lines = []
        for a in self.audits:
            lines.append(f"{'OK  ' if a.ok else 'FAIL'} {a.id}: {a.detail}")
        return "\n".join(lines)


# ------------------------------------------------------------------ PF audits
def pf0_pristine(ctx: Context) -> Audit:
    """The tree must be a pristine decode: version pinned, file count exact."""
    from patcher import anchors as A

    ver = A.detect_version(ctx.app_src)
    if ver is None:
        return Audit("PF-0", False, "apktool.yml has no versionName -- not a decode?")
    try:
        pin = config.pin_for(ver)
    except KeyError:
        return Audit("PF-0", False, f"version {ver!r} is not a pinned build")
    n = sum(1 for _ in ctx.app_src.rglob("*.smali"))
    if n != pin["smali_files"]:
        return Audit(
            "PF-0",
            False,
            f"tree holds {n:,} smali files, pristine {ver} holds "
            f"{pin['smali_files']:,} -- already patched or foreign decode? "
            f"Re-run `patcher decode` (or `all`) first.",
            {"files": n, "expected": pin["smali_files"], "version": ver},
        )
    return Audit("PF-0", True, f"pristine {ver} decode ({n:,} smali files)")


def pf1_census(ctx: Context) -> Audit:
    from patcher import inventory

    c = inventory.build(ctx.app_src)
    d = inventory.to_dict(c)
    return Audit(
        "PF-1",
        True,
        f"census measured: {d['smali_files']} files, "
        f"Set S={d['set_s_types']}, shadow={d['shadow_okhttp_files']}",
        d,
    )


def pf2_null_safety(ctx: Context) -> Audit:
    """For each ad-helper call site found by scanning (never a fixed file
    list), is an object return value null-checked? Informational only."""
    from patcher import anchors as A
    from patcher.smali.reader import iter_smali_files
    from patcher.smali.span import find_method_spans

    specs, _ver = A.specs_for(ctx.app_src)
    object_targets: set[bytes] = set()
    for key in specs:
        hit = A.resolve_method(ctx.app_src, key, A.APP_CLASS_REL)
        if hit is None:
            continue
        span, _data = hit
        if span.descriptor.split(")")[1].startswith(("L", "[")):
            object_targets.add(f"->{span.name}(".encode())
    if not object_targets:
        return Audit("PF-2", False, "no object-returning ad helpers resolvable")

    sites: dict[str, int] = {}
    unguarded: list[str] = []
    roots = [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]
    for f in iter_smali_files(roots):
        if "/com/applovin/shadow/" in f.as_posix():
            continue
        data = f.read_bytes()
        if not any(t in data for t in object_targets):
            continue
        rel = str(f.relative_to(ctx.app_src))
        for span in find_method_spans(data, f):
            body = span.body(data)
            if not any(t in body for t in object_targets):
                continue
            sites[rel] = sites.get(rel, 0) + 1
            # after move-result-object, look for a null/zero guard
            idx = body.find(b"move-result-object")
            window = body[idx : idx + 400] if idx != -1 else b""
            if not (b"if-eqz" in window or b"if-nez" in window):
                unguarded.append(f"{rel}:{span.name.split('(')[0]}")
    detail = (
        f"{sum(sites.values())} object-returning ad-helper call sites in "
        f"{len(sites)} files; {len(unguarded)} without a visible null-guard"
    )
    # informational: a missing guard is a RISK to review, not a hard failure --
    # the app's donated path already returns null, so callers are null-safe by
    # design. The verdict is carried in the report, not the exit code.
    return Audit(
        "PF-2",
        True,
        detail,
        {
            "sites": sites,
            "unguarded": unguarded[:20],
            "interpretation": "review each site; risk is low by design",
        },
    )


def pf3_fo5p_return_shape(ctx: Context) -> Audit:
    """Chokepoint call sites and whether its return value is null-checked.

    Resolved structurally via anchors.resolve_chokepoint. Fails when the
    chokepoint is unresolvable or any site is unguarded.
    """
    from patcher import anchors as A
    from patcher.smali.reader import iter_smali_files

    hit = A.resolve_chokepoint(ctx.app_src)
    if hit is None:
        return Audit(
            "PF-3",
            False,
            "backend chokepoint NOT resolvable by evidence -- cannot verify "
            "null-guards; refusing to pass",
            {"resolved": False},
        )
    _file, span, _data = hit
    ret = span.descriptor[span.descriptor.index(")") + 1 :]
    needle = f"->{span.name}({A.CHOKEPOINT_ARGS}){ret}".encode()

    checked = unchecked = 0
    samples: list[str] = []
    for f in iter_smali_files([p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]):
        data = f.read_bytes()
        for m in re.finditer(re.escape(needle), data):
            window = data[m.end() : m.end() + 300]
            guarded = (
                b"if-eqz" in window
                or b"if-nez" in window
                or (b"move-result-object" in window and b"if-" in window)
            )
            if guarded:
                checked += 1
            else:
                unchecked += 1
                if len(samples) < 5:
                    samples.append(str(f.relative_to(ctx.app_src)))
    # An unguarded site means an early `return null` would NPE. The
    # chokepoint must be found AND every site guarded.
    ok = checked > 0 and unchecked == 0
    return Audit(
        "PF-3",
        ok,
        f"{span.name}({A.CHOKEPOINT_ARGS}){ret} call sites: {checked} "
        f"null-guarded, {unchecked} not guarded",
        {
            "chokepoint": needle.decode(),
            "samples": samples,
            # A risk the OPERATOR may knowingly accept: the chokepoint change
            # would return null early, and these sites would NPE. Correctness of
            # the rest of the patch does not depend on it.
            "risk_acceptance": bool(not ok),
            "blocked_until_reviewed": unchecked,
        },
    )


def pf6_dispatchers(ctx: Context) -> Audit:
    """Any path to the backend host that bypasses the resolved chokepoint?

    Other dispatchers (OkHttp, HttpURLConnection) serve third-party APIs; only
    a file combining another dispatcher with a blocked endpoint is a bypass.
    """
    from patcher import anchors as A
    from patcher.smali.reader import iter_smali_files

    hit = A.resolve_chokepoint(ctx.app_src)
    if hit is None:
        return Audit("PF-6", False, "chokepoint unresolvable -- exclusivity unprovable")
    _file, span, _data = hit
    ret = span.descriptor[span.descriptor.index(")") + 1 :]
    dispatched = f"->{span.name}({A.CHOKEPOINT_ARGS}){ret}".encode()

    pats = (
        b"newCall(",
        b"->execute()",
        b"->enqueue(",
        b"openConnection()",
        b"Request$Builder;->url(",
        b"RealWebSocket",
    )
    bypass: list[str] = []
    other_files = 0
    for f in iter_smali_files([p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]):
        if "/com/applovin/shadow/" in f.as_posix():
            continue
        data = f.read_bytes()
        if not any(p in data for p in pats):
            continue
        other_files += 1
        # a bypass only matters if it could carry a BLOCKED endpoint
        blocked = any(b"ws/php/v4.1/" + ep.encode() in data for ep in config.BLOCKED_ENDPOINTS)
        if blocked and dispatched not in data:
            bypass.append(str(f.relative_to(ctx.app_src)))
    ok = not bypass
    detail = (
        f"{other_files} files use other dispatchers (TuneIn/Apple/Google); "
        f"backend bypasses outside {span.name}: {len(bypass)}"
    )
    return Audit("PF-6", ok, detail, {"bypass": bypass[:10]})


def pf4_zh_g_and_b(ctx: Context) -> Audit:
    """Installer gate's g() shape and reads of its isLegit field, resolved via
    the installer-gate anchor so it follows the class across obfuscation."""
    from patcher import anchors as A
    from patcher.smali.reader import SmaliFile

    try:
        r = A.resolve_class(ctx.app_src, "installer_gate")
    except Exception as exc:  # AnchorError
        return Audit(
            "PF-4", False, f"installer gate unresolvable: {str(exc)[:120]}", {"resolved": False}
        )

    sf = SmaliFile(r.path)
    g = sf.find("g", "(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z")
    head = g.body(sf.data)[:400] if g is not None else b""
    # the class's own obfuscated name, so the field probe follows it too
    decl = sf.data[sf.data.index(b".class ") : sf.data.index(b"\n")]
    # ".class public abstract Lzh;" -> "Lzh;": keep the leading L.
    name = decl.split(b"L", 1)[1].split(b";")[0].decode()
    cls = "L" + name
    flag = (cls + "->b:Z").encode()
    reads = sum(1 for sp in sf.spans if flag in sp.body(sf.data))
    # The gate must actually be inspected: an unresolvable or g()-less class is
    # a failure, not "0 reads, fine". (The read count itself is informational.)
    ok = g is not None and len(head) > 0
    return Audit(
        "PF-4",
        ok,
        f"{r.rel}: g() body begins with {len(head)} bytes; methods touching {cls}->b: {reads}",
        {
            "resolved_class": r.rel,
            "note": "zh.c() hashes yh.a and returns false when the installer is "
            "empty (sideload); zh.e() gates the donate app's installer",
        },
    )


def pf5_god_classes(ctx: Context) -> Audit:
    """Label load-bearing classes by role, resolved structurally.
    Informational only -- ok is always True.
    """
    from patcher import anchors as A
    from patcher.smali.reader import SmaliFile

    roles: dict[str, str] = {}
    hit = A.resolve_chokepoint(ctx.app_src)
    if hit is not None:
        f, _span, _data = hit
        roles["dispatcher"] = f"HTTP dispatcher, {SmaliFile(f).method_count()} methods"
    try:
        r = A.resolve_class(ctx.app_src, "installer_gate")
        roles["installer_gate"] = (
            f"signature/installer gate, {SmaliFile(r.path).method_count()} methods"
        )
    except Exception:
        roles["installer_gate"] = "unresolvable"
    # payload builder: the file holding the most blocked-endpoint literals
    best, best_n = "", 0
    for f in sorted(ctx.app_src.rglob("*.smali")):
        try:
            data = f.read_bytes()
        except OSError:
            continue
        n = sum(data.count(ep.encode()) for ep in config.BLOCKED_ENDPOINTS)
        if n > best_n:
            best, best_n = str(f.relative_to(ctx.app_src)), n
    if best:
        roles["payload_builder"] = f"telemetry payload builder ({best_n} endpoint refs)"
    # datatransport users outside firebase: the telemetry dispatch transport
    users = []
    for f in sorted(ctx.app_src.rglob("*.smali")):
        posix = f.as_posix()
        if "/com/google/firebase/" in posix or "/com/applovin/shadow/" in posix:
            continue
        if "/com/google/android/datatransport/" in posix:
            continue  # the transport's own internals, not its users
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if b"Lcom/google/android/datatransport/" in data:
            users.append(str(f.relative_to(ctx.app_src)))
            if len(users) >= 6:
                break
    if users:
        roles["datatransport"] = f"telemetry transport users: {', '.join(users[:4])}"
    return Audit("PF-5", True, "; ".join(f"{k}={v}" for k, v in roles.items()), roles)


def pf7_apktool_yml(ctx: Context) -> Audit:
    import re as _re

    yml = (ctx.app_src / "apktool.yml").read_text()
    m = _re.search(r"doNotCompress:\n((?:- .*\n)+)", yml)
    entries = [line[2:].strip() for line in m.group(1).splitlines()] if m else []
    # "arsc"/"jpg"/"png"/"so" are EXTENSIONS, not paths -- only real paths can dangle
    dangling = [
        e
        for e in entries
        if "." in e
        and e.startswith(("assets/", "res/", "lib/"))
        and not (ctx.app_src / e).is_file()
    ]
    return Audit(
        "PF-7", not dangling, f"doNotCompress entries: {len(entries)}; dangling: {dangling}", {}
    )


def pf8_signer(ctx: Context) -> Audit:
    """The decoded tree must come from an APK signed by the pinned key."""
    import subprocess  # nosec B404 -- PATH tools, never shell

    apk = ctx.source_apk or config.source_apk()
    r = subprocess.run(  # nosec B603 -- fixed apksigner argv
        [config.APKSIGNER, "verify", "--print-certs", str(apk)],
        capture_output=True,
        text=True,
    )
    ok = config.SIGNER_SHA256 in r.stdout.upper()
    return Audit(
        "PF-8",
        ok,
        f"input signer SHA-256 matches pinned ({config.SIGNER_SHA256[:12]}...): {ok} "
        f"[{Path(apk).name[:44]}]",
        {"apk": str(apk)},
    )


AUDITS = {
    "PF-0": pf0_pristine,
    "PF-1": pf1_census,
    "PF-2": pf2_null_safety,
    "PF-3": pf3_fo5p_return_shape,
    "PF-4": pf4_zh_g_and_b,
    "PF-5": pf5_god_classes,
    "PF-6": pf6_dispatchers,
    "PF-7": pf7_apktool_yml,
    "PF-8": pf8_signer,
}


def run(ctx: Context) -> PreflightResult:
    res = PreflightResult()
    for pid, fn in AUDITS.items():
        try:
            res.audits.append(fn(ctx))
        except Exception as exc:
            res.audits.append(Audit(pid, False, f"{type(exc).__name__}: {exc}"))
    # Anchors last: confidence is part of the verdict -- a low-confidence
    # anchor is a failure.
    for cls in order_patches():
        p = cls()
        try:
            found = p.resolve(ctx)
        except AnchorError as exc:
            res.audits.append(Audit(f"anchor:{p.name}", False, str(exc)))
            continue
        missing = [a for a in found if a.confidence != "high"]
        if missing:
            res.audits.append(
                Audit(
                    f"anchor:{p.name}",
                    False,
                    f"{len(found) - len(missing)}/{len(found)} anchors high-confidence; "
                    f"{len(missing)} unresolved: "
                    + ", ".join(
                        f"{a.method or a.id} ({getattr(a, 'evidence', {}).get('label', 'absent')})"
                        for a in missing[:4]
                    ),
                    {"missing": [a.id for a in missing]},
                )
            )
        else:
            res.audits.append(
                Audit(f"anchor:{p.name}", True, f"{len(found)} resolved (all high-confidence)")
            )
    return res
