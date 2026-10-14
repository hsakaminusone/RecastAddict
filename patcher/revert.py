"""Restore files from the journal.

The journal stores the ORIGINAL BYTES of every file a patch rewrote, under
.journal/<module>/<idx>_<filename>. Restoring is therefore exact.
NOTE: tree *deletions* are not reversible this way -- use `patcher decode` to
regenerate app_src/ from the pinned APK, which is the ground-truth reset.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree.ElementTree import fromstring  # nosec B405 -- own journal snapshot

from patcher import config

_IDX_RE = re.compile(r"^(\d{4})_(.*)$")


def _restore_manifest(ctx_src_name: str, snap: Path, app_src: Path) -> bool:
    """Restore AndroidManifest.xml from the JSON snapshot ads.py wrote."""
    try:
        xml = json.loads(snap.read_bytes())["xml"]
        # Snapshot was written by our own journal, not untrusted input.
        fromstring(xml)  # noqa: S314  # nosec B314 -- own journal snapshot
        # Manifest.save() writes with an XML declaration; restore the same shape
        # so a revert is byte-comparable to the pristine decode.
        (app_src / "AndroidManifest.xml").write_text(
            "<?xml version='1.0' encoding='utf-8'?>\n" + xml, encoding="utf-8"
        )
        return True
    except Exception as exc:
        print(f"  {ctx_src_name}: manifest snapshot unusable: {exc}")
        return False


def run(module: str | None = None) -> int:
    if not config.JOURNAL_DIR.is_dir():
        print("no journal found -- nothing to revert")
        return 0
    mods = (
        [module] if module else [p.name for p in sorted(config.JOURNAL_DIR.iterdir()) if p.is_dir()]
    )
    if not mods:
        print("no journal found -- nothing to revert")
        return 0
    for mod in mods:
        d = config.JOURNAL_DIR / mod
        if not d.is_dir():
            print(f"  {mod}: no journal entries")
            continue
        n = 0
        for snap in sorted(d.iterdir()):
            if snap.name == "manifest.json":
                if _restore_manifest(mod, snap, config.APP_SRC):
                    n += 1
                continue
            m = _IDX_RE.match(snap.name)
            if not m:
                print(f"  {mod}: skipping unrecognised journal entry {snap.name}")
                continue
            rel = m.group(2).replace("__", "/")  # undo _journal_key's escaping
            target = config.APP_SRC / rel
            if not target.is_file():
                print(f"  {mod}: cannot locate {rel} in app_src")
                continue
            target.write_bytes(snap.read_bytes())
            n += 1
        print(f"  {mod}: restored {n} file(s)")
    return 0
