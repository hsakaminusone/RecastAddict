"""apktool b -> extract dex -> d8 -> repack -> zipalign -> sign."""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 -- PATH tools, never shell
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from patcher import config
from patcher.patches.base import Context


def _run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)  # nosec


def _dex_reoptimise(apk: Path, out_dir: Path) -> str | None:
    """Extract classes*.dex, run d8, repack a new APK.

    Returns None on success, else the error text. Reporting is the caller's
    job -- returning a bool after printing inside hid d8's stderr behind a
    generic "skipped" line.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        with zipfile.ZipFile(apk) as z:
            dexes = [n for n in z.namelist() if n.startswith("classes") and n.endswith(".dex")]
            if not dexes:
                return "no classes*.dex entries in apktool output"
            for n in dexes:
                z.extract(n, td)
        dexout = td / "out"
        dexout.mkdir()
        r = _run(
            [config.D8, "--release", "--min-api", str(config.MIN_SDK), "--output", str(dexout)]
            + [str(td / n) for n in dexes]
        )
        if r.returncode != 0:
            return r.stderr[-1500:] or "d8 exited nonzero with no stderr"
        # Build a FRESH zip: copy every original entry except the dex files,
        # then add the d8 output. Appending to the original zip leaves duplicate
        # classes*.dex entries, which apksigner rejects outright.
        new_dex = {f.name: f.read_bytes() for f in sorted(dexout.glob("*.dex"))}
        rebuilt = apk.with_suffix(".redexed.apk")
        with (
            zipfile.ZipFile(apk) as zin,
            zipfile.ZipFile(rebuilt, "w", zipfile.ZIP_DEFLATED) as zout,
        ):
            for item in zin.infolist():
                if item.filename in new_dex:
                    continue
                data = zin.read(item.filename)
                zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
                zi.compress_type = item.compress_type
                zi.external_attr = item.external_attr
                zout.writestr(zi, data)
            for name, data in new_dex.items():
                zout.writestr(name, data)
        shutil.move(str(rebuilt), str(out_dir))
        return None


def _fail(step: str, err: str) -> int:
    """Report a build failure and return a NON-ZERO exit code."""
    print(f"BUILD FAIL at {step}:\n{err[-1500:]}")
    return 1


def run(ctx: Context, name: str = "recast") -> int:
    config.OUT_DIR.mkdir(parents=True, exist_ok=True)
    unsigned = config.OUT_DIR / f"{name}.raw.apk"

    print("==> apktool build")
    r = _run([config.APKTOOL, "b", str(ctx.app_src), "-o", str(unsigned)])
    if r.returncode != 0:
        return _fail("apktool b", r.stderr)
    print(f"    {unsigned.stat().st_size:,} bytes")

    print("==> d8 dex re-optimisation")
    d8_err = _dex_reoptimise(unsigned, config.OUT_DIR / f"{name}.redexed.apk")
    if d8_err is not None:
        print(f"    d8 failed, using apktool dex as-is:\n{d8_err[-500:]}")

    print("==> zipalign")
    src = config.OUT_DIR / f"{name}.redexed.apk"
    if not src.exists():
        shutil.copy(unsigned, src)
    aligned = config.OUT_DIR / f"{name}.aligned.apk"
    if _run([config.ZIPALIGN, "-p", "-f", "4", str(src), str(aligned)]).returncode != 0:
        return _fail("zipalign", "nonzero exit")

    print("==> apksigner")
    final = config.OUT_DIR / f"{name}.apk"
    keystore, alias, ks_pass, key_pass = config.signing_config()
    cmd = [
        config.APKSIGNER,
        "sign",
        "--ks",
        str(keystore),
        "--ks-key-alias",
        alias,
        "--ks-pass",
        ks_pass,
        "--key-pass",
        key_pass,
        "--v1-signing-enabled",
        "false",  # saves 813 KB of junk META-INF
        "--v2-signing-enabled",
        "true",
        "--v3-signing-enabled",
        "true",
        "--out",
        str(final),
        str(aligned),
    ]
    r = _run(cmd)
    if r.returncode != 0:
        return _fail("apksigner", (r.stderr or r.stdout))

    print("==> verify")
    v = _run([config.APKSIGNER, "verify", "--verbose", str(final)])
    ok = "Verifies" in v.stdout
    for line in v.stdout.splitlines():
        if "scheme" in line:
            print("    " + line.strip())
    orig = config.source_apk().stat().st_size
    size = final.stat().st_size
    print(f"\nBUILT  {final}")
    print(
        f"  original {orig:,}  ->  patched {size:,}  "
        f"({size - orig:+,}, {100 * (size - orig) / orig:+.1f}%)"
    )
    return 0 if ok else 1
