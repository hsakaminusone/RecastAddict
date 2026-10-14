"""patcher CLI: one command, one input, one output.

Takes a pinned Podcast Addict APK, decodes it fresh, runs preflight,
applies the behaviour-tier patches, rebuilds, verifies, and writes
RecastAddict-<version>.apk next to the input.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from typing import TYPE_CHECKING

from patcher import config

if TYPE_CHECKING:
    from patcher.patches.base import Context


def _ctx(dry_run: bool = False) -> Context:
    from patcher.patches.base import Context

    return Context(
        app_src=config.APP_SRC,
        anchors_dir=config.ANCHORS_DIR,
        journal_dir=config.JOURNAL_DIR,
        offline=dry_run,
        source_apk=None,  # set by _ctx_for_tree() from the selected input
    )


def _ctx_for_tree(dry_run: bool = False) -> Context:
    """A context whose source_apk is the selected input.

    The CLI always decodes the selected input fresh, so the tree in app_src/
    comes from that APK. PF-0 independently verifies the tree is pristine.
    """
    ctx = _ctx(dry_run=dry_run)
    ctx.source_apk = config.source_apk()
    return ctx


def _reset_generated_anchors() -> None:
    """Drop regenerable anchor artifacts after a fresh decode.

    shims.txt and deleted_sdk_classes.json describe the PATCHED tree (and the
    build it came from). A fresh decode wipes app_src/ but not anchors/, so
    the next shim run would inherit another version's manifest and shape cache
    -- descriptors collide across obfuscated builds with different shapes
    (Am.smali surviving into a build that only has am). Both files regenerate
    from the source APK on demand; deleting them is always safe.
    """
    for name in ("shims.txt", "deleted_sdk_classes.json"):
        (config.ANCHORS_DIR / name).unlink(missing_ok=True)


def _patches() -> dict[str, type]:
    from patcher.patches import order_patches

    return {c.name: c for c in order_patches()}


def _os_label() -> str:
    plat: str = sys.platform
    if plat == "darwin":
        return "macOS"
    if plat.startswith("linux"):
        return "Linux"
    if plat in ("win32", "cygwin"):
        return "Windows"
    return "this system"


def check_deps() -> list[str]:
    """Human-readable list of missing dependencies, empty when all present.

    Every problem names the fix for the OS this runs on. Runs before
    anything else so a missing tool fails fast with steps instead of
    mid-pipeline with a traceback.
    """
    problems: list[str] = []
    if sys.platform == "darwin":
        py_fix = "brew install python@3.11 (or from python.org)"
        apktool_fix = "brew install apktool"
        jdk_fix = (
            'brew install openjdk@17, then export PATH="$(brew --prefix openjdk@17)/bin:$PATH"'
        )
        sdk_fix = (
            "install SDK cmdline-tools, then "
            'sdkmanager "build-tools;35.0.0", then '
            "add <sdk>/build-tools/35.0.0 to PATH (see README Dependencies)"
        )
    elif sys.platform.startswith("linux"):
        py_fix = "sudo apt install python3 (or from python.org)"
        apktool_fix = "sudo apt install apktool (or the apktool install guide)"
        jdk_fix = "sudo apt install openjdk-17-jdk"
        sdk_fix = (
            "install SDK cmdline-tools, then "
            'sdkmanager "build-tools;35.0.0", then '
            "add <sdk>/build-tools/35.0.0 to PATH (see README Dependencies)"
        )
    elif sys.platform in ("win32", "cygwin"):
        py_fix = "winget install Python.Python.3.11 (or from python.org)"
        apktool_fix = "scoop install apktool (or the apktool install guide)"
        jdk_fix = "winget install Microsoft.OpenJDK.17"
        sdk_fix = (
            'sdkmanager "build-tools;35.0.0", then '
            "add <sdk>\\build-tools\\35.0.0 to PATH (see README Dependencies)"
        )
    else:
        py_fix = "install from python.org"
        apktool_fix = "follow the apktool official install guide"
        jdk_fix = "install a JDK 17+ and put java and keytool on PATH"
        sdk_fix = (
            'sdkmanager "build-tools;35.0.0", then '
            "put build-tools/35.0.0 on PATH (see README Dependencies)"
        )
    if sys.version_info < (3, 9):  # noqa: UP036 -- direct script runs bypass packaging guards
        problems.append(
            "Python 3.9 or newer is required "
            f"(found {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"  fix ({_os_label()}): {py_fix}"
        )
    fixes = {
        config.APKTOOL: apktool_fix,
        config.AAPT2: sdk_fix,
        config.ZIPALIGN: sdk_fix,
        config.APKSIGNER: sdk_fix,
        config.D8: sdk_fix,
        config.JAVA: jdk_fix,
        config.KEYTOOL: jdk_fix,
    }
    for tool, fix in fixes.items():
        if shutil.which(tool) is None:
            problems.append(f"{tool} not found on PATH.\n  fix ({_os_label()}): {fix}")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="patcher",
        description="Patch a Podcast Addict APK. "
        "Takes an APK, writes RecastAddict-<version>.apk next to it.",
        epilog="Requires on PATH: apktool, aapt2, zipalign, apksigner, d8, "
        "java, keytool (missing tools are reported with install steps; "
        "see README Dependencies).",
    )
    ap.add_argument("apk", help="path to the source APK")
    args = ap.parse_args(argv)

    missing = check_deps()
    if missing:
        print("MISSING DEPENDENCIES:\n")
        for m in missing:
            print(f"- {m}\n")
        return 1

    import subprocess  # nosec B404 -- PATH tools, never shell

    from patcher import build as b
    from patcher import policy, preflight

    try:
        apk, pin = config.select_input(args.apk)
    except Exception as exc:
        print(f"INPUT FAIL: {exc}")
        return 1
    print(f"INPUT  {pin['version_name']} ({pin['version_code']}) [{apk.name}]")

    try:
        policy.check(config.source_apk())
    except Exception as exc:
        print(f"POLICY FAIL: {exc}")
        return 1

    print("==> decoding pristine tree")
    cmd = [config.APKTOOL, "d", "-f", str(config.source_apk()), "-o", str(config.APP_SRC)]
    r = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
    if r.returncode:
        print(r.stderr[-1500:])
        return 1
    for ds in config.APP_SRC.rglob(".DS_Store"):
        ds.unlink()
    _reset_generated_anchors()

    res = preflight.run(_ctx_for_tree(dry_run=True))
    print(res.summary())
    safety = [a for a in res.failures if not a.data.get("risk_acceptance")]
    accepted_risks = [a for a in res.failures if a.data.get("risk_acceptance")]
    if safety:
        print(f"\nPREFLIGHT FAILED: {len(safety)} audit(s) -- cannot proceed")
        return 1
    if accepted_risks:
        print(f"\nWARN: proceeding past {len(accepted_risks)} known-risk audit(s):")
        for a in accepted_risks:
            print(f"  - {a.id}: {a.detail}")

    print("\n=== patching ===")
    ctx = _ctx_for_tree()
    for patch_cls in _patches().values():
        p = patch_cls()
        r = p.apply(ctx)
        print(f"[{p.tier}] {p.name}: applied={r.applied} already={r.already}")

    out_name = f"RecastAddict-{pin['version_name']}"
    rc = b.run(ctx, out_name)
    if rc:
        return rc
    final = config.OUT_DIR / f"{out_name}.apk"
    target = apk.parent / f"{out_name}.apk"
    if target.exists() and target.samefile(final):
        print(f"\nDONE  {final} (already next to the input)")
        return 0
    if target.resolve() == apk.resolve():
        # The input itself carries the output name: never overwrite the source.
        target = apk.parent / f"{out_name}-patched.apk"
    shutil.copy(final, target)
    print(f"\nDONE  {target}")

    print("\n=== verify ===")
    bad = 0
    for patch_cls in _patches().values():
        for line in patch_cls().verify(ctx):
            print("  " + line)
            bad += line.startswith("FAIL")
    if accepted_risks:
        print("\nNOTE: built past known-risk audit(s): " + ", ".join(a.id for a in accepted_risks))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
