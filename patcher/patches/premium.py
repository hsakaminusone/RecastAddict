"""MODULE premium -- unlock subscription, kill donate checks.

Stubs eight methods across two obfuscated classes, on all four pinned builds.
2026.13 moved two premium roles (ad_gates g->h, upsell k->l); the patches
address them by role, the name is release data in CLASS_PROFILES.

Why stubbing the subscription predicate directly is required: it returns
``installer.g() && (!Application.s1 || pref_previousTimerUpdate)``. Even with
the installer helper stubbed true, a real billing purchase is still needed --
so stubbing only the helper is the single most common mistake in entitlement
patches.

The cert allowlist is stubbed because we re-sign with a new key and our cert is
not in the allowlist -- and cannot be added: the comparison surface includes
MD5 and a 96-hex (SHA-384) digest that the corpus never documented.

installer d() is deliberately NOT stubbed: its semantics are unknown and
stubbing unknown predicates to true can route UI down odd paths (preflight
PF-4).

HOW TARGETS ARE FOUND

Both classes are R8-obfuscated and were RENAMED between builds (y31 -> f41 ->
k61 -> ub1, zh -> ci -> oj -> xl). Naming them would resolve the WRONG FILE on
a newer build and patch an innocent class. Targets are located by structural
evidence instead (see anchors.py), so a rename is survivable and a real
structural change is loud.
"""

from __future__ import annotations

from pathlib import Path

from patcher import anchors as A
from patcher.patches.base import Anchor, AnchorError, Context, Patch, PatchResult
from patcher.smali.editor import apply_edits, stub_method
from patcher.smali.reader import SmaliFile

# (anchor key, role, descriptor, reason, stub_value)
#
# Method names come from anchors.class_role_name (BASE_CLASS_ROLES plus
# CLASS_PROFILES), because 2026.13 moved ad_gates g->h and upsell k->l.
#
# Stub the upsell gate to FALSE so the "Remove Ad" upsell stays hidden.
TARGETS = [
    (
        "premium_gate",
        "subscription",
        "()Z",
        "subscription active: unlocks sync, WebSub, locked prefs, customization",
        1,
    ),
    (
        "premium_gate",
        "donate_app",
        "(Landroid/content/Context;)Z",
        "donate app present: sync needs donate AND subscription",
        1,
    ),
    ("premium_gate", "ad_gates", "(Landroid/content/Context;)Z", "ad gates closed", 1),
    (
        "premium_gate",
        "upsell",
        "(Landroid/content/Context;)Z",
        "HIDE the Remove-Ad upsell",
        0,
    ),
    ("installer_gate", "iap_can_use", "()Z", "IAPHelper.canUse()", 1),
    (
        "installer_gate",
        "cert_allowlist",
        "(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z",
        "cert allowlist always passes (we re-sign)",
        1,
    ),
    ("installer_gate", "installer_allowlist", "()Z", "installer allowlist always passes", 1),
    ("installer_gate", "donate_installer", "()Z", "donate-app installer allowlist passes", 1),
]

# 13/14 split a pure-state g()Z out of f(); the most-called premium predicate
# (45-48 sites) and absent on 11/12/12.1, so it is stubbed only when mapped.
OPTIONAL_TARGETS = [
    ("premium_gate", "premium_state", "()Z", "raw premium state (split from f in 13+)", 1),
]


def _targets(ctx: Context) -> list[tuple[str, str, str, str, str, int]]:
    """(key, role, method, desc, reason, value) present in this build."""
    out = []
    for key, role, desc, reason, value in TARGETS + OPTIONAL_TARGETS:
        method = A.class_role_name(ctx.app_src, key, role)
        if method is None:
            continue
        out.append((key, role, method, desc, reason, value))
    return out


def _locate(ctx: Context, key: str) -> tuple[Path, str]:
    """Resolve an anchor key to a concrete smali file. Raises AnchorError."""
    r = A.resolve_class(ctx.app_src, key)
    return ctx.app_src / r.rel, r.rel


class PremiumPatch(Patch):
    name = "premium"
    tier = "behaviour"

    def resolve(self, ctx: Context) -> list[Anchor]:
        out = []
        for key, role, method, desc, _why, _val in _targets(ctx):
            path, rel = _locate(ctx, key)
            sf = SmaliFile(path)
            span = sf.find(method, desc)
            if span is None:
                raise AnchorError(
                    f"premium: {method}{desc} not found in {rel} "
                    f"({key}:{role}); class has "
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
        for key, _role, method, desc, reason, value in _targets(ctx):
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

        for key, _role, method, desc, _why, value in _targets(ctx):
            path, rel = _locate(ctx, key)
            sf = SmaliFile(path)
            span = sf.find(method, desc)
            ret = desc[desc.index(")") + 1 :]
            ok = span is not None and is_stub(sf.data, span, ret, value)
            out.append(f"{'OK ' if ok else 'FAIL'} {rel} {method}{desc} stubbed")
        for key, role, _desc, _why, _val in OPTIONAL_TARGETS:
            if A.class_role_name(ctx.app_src, key, role) is None:
                out.append(f"n/a  {role} absent in this build")
        return out
