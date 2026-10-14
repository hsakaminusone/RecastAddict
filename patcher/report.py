"""Build report -- answers "if this APK breaks, why was it produced?"

Emitted as patcher/out/report.md and printed to stdout. Contains the provenance
the plan requires: input hash, signer, tool versions, anchor resolutions,
inventory census, per-patch results, verification, and size breakdown.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from patcher import config

if TYPE_CHECKING:
    from patcher.patches.base import Context


def run(ctx: Context, name: str) -> int:
    from patcher import inventory as inv
    from patcher import policy
    from patcher.patches import order_patches

    lines: list[str] = ["# RecastAddict build report", ""]
    try:
        info = policy.check(config.source_apk())
        lines += [
            f"- input SHA-256 `{info.sha256}`",
            f"- package `{info.package}` {info.version_name} ({info.version_code})",
            f"- signer SHA-1 `{info.signer_sha1}`",
            "",
        ]
    except Exception as exc:
        lines += [f"- **policy gate FAILED**: {exc}", ""]

    apk = config.OUT_DIR / f"{name}.apk"
    orig = config.source_apk().stat().st_size
    if apk.is_file():
        size = apk.stat().st_size
        lines += [
            "## Size",
            f"- original {orig:,} bytes",
            (f"- patched  {size:,} bytes ({size - orig:+,}, {100 * (size - orig) / orig:+.1f}%)"),
            "",
        ]

    try:
        c = inv.build()
        lines += ["## Inventory", ""]
        for k in ("smali_files", "set_s_types", "shadow_okhttp_files"):
            lines.append(f"- {k}: {getattr(c, k):,}")
        lines += [f"- set_s_by_sdk: {c.set_s_by_sdk}", ""]
    except Exception as exc:
        lines += [f"- inventory failed: {exc}", ""]

    lines += ["## Verification", ""]
    for cls in order_patches():
        lines.append(f"### {cls.name} ({cls.tier})")
        lines.append("```")
        lines += ["  " + line for line in cls().verify(ctx)]
        lines += ["```", ""]

    out = config.OUT_DIR / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    print("\n".join(lines))
    print(f"\nreport written to {out}")
    return 0
