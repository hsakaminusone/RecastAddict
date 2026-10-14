"""MODULE premium -- unlock subscription, kill donate checks.

Stubs six methods across two obfuscated classes. Verified against the decoded
tree of the pinned 2026.11 APK, and re-resolvable on 2026.12 without change
(see patcher/anchors.py for how).

Why stubbing y31.f() directly is required: it returns
``zh.f() && (!Application.s1 || pref_previousTimerUpdate)``. Even with zh.f()
stubbed true, a real billing purchase is still needed -- so stubbing only the
zh helper is the single most common mistake in entitlement patches.

zh.g() is stubbed because we re-sign with a new key and our cert is not in the
allowlist -- and cannot be added: the comparison surface includes MD5 and a
96-hex (SHA-384) digest that the corpus never documented.

zh.c/d/e are deliberately NOT stubbed: their semantics are unknown and stubbing
unknown predicates to true can route UI down odd paths (preflight PF-4).

HOW TARGETS ARE FOUND

Both classes are R8-obfuscated and were RENAMED between the 2026.11 and 2026.12
builds of the app (y31 -> f41, zh -> ci). Naming them would therefore resolve
the WRONG FILE on 2026.12 -- the old names now point at unrelated classes --
and patch would silently touch an innocent class instead of failing. Targets
are located by structural evidence instead (see anchors.py), so a rename is
survivable and a real structural change is loud.
"""

from __future__ import annotations

from pathlib import Path

from patcher import anchors as A
from patcher.patches.base import Anchor, AnchorError, Context, Patch, PatchResult
from patcher.smali.editor import apply_edits, stub_method
from patcher.smali.reader import SmaliFile

# (anchor key, method, descriptor, reason, stub_value)
#
# Stub the upsell gate to FALSE so the "Remove Ad" upsell stays hidden.
TARGETS = [
    (
        "premium_gate",
        "f",
        "()Z",
        "subscription active: unlocks sync, WebSub, locked prefs, customization",
        1,
    ),
    (
        "premium_gate",
        "d",
        "(Landroid/content/Context;)Z",
        "donate app present: sync needs donate AND subscription",
        1,
    ),
    ("premium_gate", "g", "(Landroid/content/Context;)Z", "ad gates closed", 1),
    (
        "premium_gate",
        "k",
        "(Landroid/content/Context;)Z",
        "HIDE the Remove-Ad upsell",
        0,
    ),
    ("installer_gate", "f", "()Z", "IAPHelper.canUse()", 1),
    (
        "installer_gate",
        "g",
        "(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z",
        "cert allowlist always passes (we re-sign)",
        1,
    ),
    # zh.c()/zh.e() are the installer/donate-app gates.
    (
        "installer_gate",
        "c",
        "()Z",
        "installer allowlist always passes",
        1,
    ),
    (
        "installer_gate",
        "e",
        "()Z",
        "donate-app installer allowlist always passes",
        1,
    ),
]


def _locate(ctx: Context, key: str) -> tuple[Path, str]:
    """Resolve an anchor key to a concrete smali file. Raises AnchorError."""
    r = A.resolve_class(ctx.app_src, key)
    return ctx.app_src / r.rel, r.rel


class PremiumPatch(Patch):
    name = "premium"
    tier = "behaviour"

    def resolve(self, ctx: Context) -> list[Anchor]:
        out = []
        for key, method, desc, _why, _val in TARGETS:
            path, rel = _locate(ctx, key)
            sf = SmaliFile(path)
            span = sf.find(method, desc)
            if span is None:
                raise AnchorError(
                    f"premium: {method}{desc} not found in {rel} "
                    f"({key}); class has "
                    f"{[s.name + s.descriptor for s in sf.spans]}"
                )
            out.append(
                Anchor(
                    id=f"{rel}:{method}",
                    file=rel,
                    descriptor=desc,
                    method=method,
                    evidence={"resolved_by": key, "file": rel},
                )
            )
        return out

    def apply(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        # Apply one edit at a time: targets share a class, batching clobbers.
        for key, method, desc, reason, value in TARGETS:
            path, rel = _locate(ctx, key)
            e = stub_method(SmaliFile(path), method, desc, reason=reason, value=value)
            label = f"{rel}:{method}"
            if e is None:
                res.already += 1
                res.note(f"already stubbed: {label}")
                continue
            if ctx.offline:
                res.note(f"[dry-run] would stub {label}")
                continue
            apply_edits([e], ctx.journal_dir, "premium", ctx.app_src)
            res.files.append(e.path)
            res.applied += 1
            res.note(f"stubbed {label}")
        return res

    def verify(self, ctx: Context) -> list[str]:
        out = []
        from patcher.smali.editor import is_stub

        for key, method, desc, _why, value in TARGETS:
            path, rel = _locate(ctx, key)
            sf = SmaliFile(path)
            span = sf.find(method, desc)
            ret = desc[desc.index(")") + 1 :]
            ok = span is not None and is_stub(sf.data, span, ret, value)
            out.append(f"{'OK ' if ok else 'FAIL'} {rel} {method}{desc} stubbed")
        return out
