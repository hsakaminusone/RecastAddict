"""File surgery: manifest edits remove ad components, journal + revert restores bytes."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from xml.etree.ElementTree import tostring

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from patcher import config
from patcher.manifest import Manifest
from patcher.patches.base import Context
from patcher.smali.editor import Edit, apply_edits

XML = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.bambuna.podcastaddict">
  <application>
    <activity android:name="com.bambuna.podcastaddict.activity.LauncherActivity"
  android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
      </intent-filter>
    </activity>
    <activity android:name="com.google.android.gms.ads.AdActivity"
  android:exported="false" />
    <provider android:name="com.google.android.gms.ads.MobileAdsInitProvider"
      android:exported="false" />
    <meta-data android:name="com.google.android.gms.ads.APPLICATION_ID"
  android:value="ca-app-pub-x" />
    <meta-data android:name="com.google.android.c2dm.API_KEY" android:value="keep" />
  </application>
</manifest>
"""

JOURNAL_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
  <application android:name=".App">
    <provider android:name="com.google.android.gms.ads.MobileAdsInitProvider"
      android:exported="false" />
  </application>
</manifest>
"""


def _load(tmp: Path) -> tuple[Manifest, Path]:
    mp = tmp / "AndroidManifest.xml"
    mp.write_text(XML)
    return Manifest.load(mp), mp


def _ctx(tmp: Path) -> Context:
    return Context(
        app_src=tmp / "app_src",
        anchors_dir=tmp / "anchors",
        journal_dir=tmp / "journal",
        offline=False,
    )


def _revert(module: str, journal_dir: Path, app_src: Path) -> None:
    old_j, old_a = config.JOURNAL_DIR, config.APP_SRC
    config.JOURNAL_DIR, config.APP_SRC = journal_dir, app_src
    try:
        from patcher import revert

        assert revert.run(module) == 0
    finally:
        config.JOURNAL_DIR, config.APP_SRC = old_j, old_a


def test_prefix_removal_keeps_first_party() -> None:
    with tempfile.TemporaryDirectory() as td:
        m, mp = _load(Path(td))
        victim = m.names_matching(["com.google.android.gms.ads"])
        assert len(victim) == 2, [c.name for c in victim]
        for c in victim:
            assert m.remove(c)
        m.save()
        names = {c.name for c in Manifest.load(mp).components()}
        assert "com.bambuna.podcastaddict.activity.LauncherActivity" in names
        assert not any("gms.ads" in n for n in names)


def test_meta_data_exact_key_only() -> None:
    with tempfile.TemporaryDirectory() as td:
        m, mp = _load(Path(td))
        assert m.remove_meta_data("com.google.android.gms.ads.APPLICATION_ID")
        assert not m.remove_meta_data("com.google.android.gms.ads.APPLICATION_ID")
        m.save()
        keys = {k for k, _ in Manifest.load(mp).meta_datas()}
        assert "com.google.android.gms.ads.APPLICATION_ID" not in keys
        assert "com.google.android.c2dm.API_KEY" in keys


def test_exported_check_flags_intent_filter() -> None:
    with tempfile.TemporaryDirectory() as td:
        m, _ = _load(Path(td))
        assert m.check() == [], m.check()


def test_edit_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _ctx(tmp)
        target = ctx.app_src / "smali" / "a.smali"
        target.parent.mkdir(parents=True)
        original = b".class public La;\n.super Ljava/lang/Object;\n"
        target.write_bytes(original)
        edit = Edit(
            path=target, old_bytes=original, new_bytes=original + b"# touched\n", reason="t"
        )
        apply_edits([edit], ctx.journal_dir, "m", ctx.app_src)
        assert target.read_bytes() != original
        _revert("m", ctx.journal_dir, ctx.app_src)
        assert target.read_bytes() == original


def test_manifest_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        ctx = _ctx(tmp)
        ctx.app_src.mkdir(parents=True)
        (ctx.app_src / "AndroidManifest.xml").write_text(JOURNAL_MANIFEST)
        m = Manifest.load(ctx.app_src / "AndroidManifest.xml")
        assert m.remove_meta_data("no.such.key") is False
        jdir = ctx.journal_dir / "ads"
        jdir.mkdir(parents=True)
        (jdir / "manifest.json").write_text(
            json.dumps({"xml": tostring(m.root, encoding="unicode")})
        )
        comps = m.names_matching(["com.google.android.gms.ads"])
        assert len(comps) == 1 and m.remove(comps[0])
        m.save()
        assert "MobileAdsInitProvider" not in (ctx.app_src / "AndroidManifest.xml").read_text()
        _revert("ads", ctx.journal_dir, ctx.app_src)
        assert "MobileAdsInitProvider" in (ctx.app_src / "AndroidManifest.xml").read_text()


def main() -> int:
    test_prefix_removal_keeps_first_party()
    test_meta_data_exact_key_only()
    test_exported_check_flags_intent_filter()
    test_edit_roundtrip()
    test_manifest_roundtrip()
    print("PASS - manifest surgery removes ads; journal revert restores bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
