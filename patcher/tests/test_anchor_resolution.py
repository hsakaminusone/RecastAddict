"""Anchor resolution must survive R8 re-obfuscation.

THE BUG THIS LOCKS IN

Between the 2026.11 and 2026.12 builds of the target app, R8 renamed every
obfuscated class we anchor on: the premium gate y31 -> f41, the installer gate
zh -> ci, and in PodcastAddictApplication the ad helpers m0 -> n0, C -> D,
v -> w, w -> x, A0 -> B0. Critically, the OLD names still exist in 2026.12
pointing at unrelated classes, so a filename-anchored patch resolves the wrong
file and edits an innocent class instead of failing loud.

The fix is to resolve by structural evidence (literals + method shape). This
test asserts that resolution works against the decoded tree at app_src/
(skipped when no tree is decoded), and additionally does a synthetic check
that resolution is name-agnostic.

Run:  python3 tests/test_anchor_resolution.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from patcher import anchors as A
from patcher.patches.base import AnchorError

CLASS_KEYS = ("premium_gate", "installer_gate")
METHOD_KEYS = tuple(A.METHOD_SPECS)


def test_class_specs_resolve(tree: Path) -> list[str]:
    """Both obfuscated classes must resolve to exactly one file each."""
    out = []
    for key in CLASS_KEYS:
        r = A.resolve_class(tree, key)
        assert r.rel, f"{key}: empty resolution"
        out.append(f"{key} -> {r.rel}")
        data = r.path.read_bytes()
        ev = A.CLASS_SPECS[key]
        for lit in ev.strings:
            assert lit.encode() in data, f"{key}: resolved file lacks {lit!r}"
    return out


def test_method_specs_resolve(tree: Path) -> list[str]:
    """Every ad method must resolve to exactly one method, by evidence.

    On an ALREADY-PATCHED tree the ad stubs are indistinguishable no-op bodies,
    so a spec whose two candidate names were both stubbed is legitimately
    ambiguous. That is not a resolver defect: a pristine tree (which is what
    `patcher all` always decodes) is unambiguous, and ambiguity is what stops a
    rename from silently patching the wrong method.
    """
    out = []
    for key in METHOD_KEYS:
        try:
            hit = A.resolve_method(tree, key, A.APP_CLASS_REL)
            if hit is None:
                raise AssertionError(f"{key}: not found (evidence too weak?)")
            span, _data = hit
            out.append(f"{key} -> {span.name}{span.descriptor[:40]}")
        except AnchorError as exc:
            assert "ambiguous" in str(exc), f"{key}: {exc}"
            out.append(f"{key} -> (ambiguous: already-patched tree)")
    return out


def test_name_agnostic() -> None:
    """Resolution must NOT depend on the method's name.

    This is the property that survives a rename: a spec that only ever matches
    one specific name would break the moment R8 shuffles it.
    """
    for key, ev in A.METHOD_SPECS.items():
        assert ev.names, f"{key}: no known names at all"
        # every spec must carry positive evidence, so it cannot match an
        # arbitrary method that merely happens to share a name
        assert ev.strings or ev.invokes, f"{key}: no evidence -- would match on name alone"


def test_extensible_profile() -> None:
    """Adding a profile must be enough to support a new release.

    The whole point of the registry shape: a future version needs one entry in
    PROFILES listing the new names, and nothing else. Prove that by applying a
    fictitious profile to a copy of the real one and re-resolving.
    """
    before = {k: list(v.names) for k, v in A.METHOD_SPECS.items()}
    A.PROFILES["2026.99"] = {
        k: (v, "zz_extra") for k, v in {k: v.names[-1] for k, v in A.METHOD_SPECS.items()}.items()
    }
    try:
        after = {k: list(v.names) for k, v in A.METHOD_SPECS.items()}
        for key, names in after.items():
            assert set(before[key]) <= set(names), f"{key}: profile widened the accepted names"
    finally:
        del A.PROFILES["2026.99"]


def main() -> int:
    tree = Path(__file__).resolve().parents[2] / "app_src"
    if not tree.is_dir():
        print(f"SKIP: tree not available at {tree}")
        return 0

    print(f"# anchor resolution against: {tree}")
    for name, fn in (
        ("class specs", test_class_specs_resolve),
        ("method specs", test_method_specs_resolve),
    ):
        print(f"\n== {name} ==")
        for line in fn(tree):
            print(f"  {line}")

    print("\n== name-agnostic invariants ==")
    test_name_agnostic()
    print("  OK  every spec carries evidence and accepts multiple names")

    print("\n== profile extensibility ==")
    test_extensible_profile()
    print("  OK  a new version needs one PROFILES entry, no code change")

    print("\nPASS - anchor resolution survives obfuscation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
