"""Reachability roots and the forbid-list never appear in the DCE proposal.

Run directly:   python3 tests/test_graph_roots.py
Or via pytest:  pytest tests/test_graph_roots.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from patcher import graph

APP = """\
.class public Lcom/bambuna/App;
.super Landroid/app/Application;
.method public onCreate()V
    .locals 1
    const-string v0, "com.example.Worker"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0
    return-void
.end method
"""

WORKER = """\
.class public Lcom/example/Worker;
.super Ljava/lang/Object;
.method public run()V
    .locals 0
    return-void
.end method
"""

ISLAND = """\
.class public Lcom/inmobi/Island;
.super Ljava/lang/Object;
.method public ping()V
    .locals 0
    return-void
.end method
"""

MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bambuna">
  <application android:name="com.bambuna.App">
    <activity android:name="com.bambuna.App" android:exported="true" />
  </application>
</manifest>
"""


def _tree(tmp: Path) -> Path:
    root = tmp / "smali"
    (root / "com" / "bambuna").mkdir(parents=True)
    (root / "com" / "bambuna" / "App.smali").write_text(APP)
    (root / "com" / "example").mkdir(parents=True)
    (root / "com" / "example" / "Worker.smali").write_text(WORKER)
    (root / "com" / "inmobi").mkdir(parents=True)
    (root / "com" / "inmobi" / "Island.smali").write_text(ISLAND)
    (tmp / "AndroidManifest.xml").write_text(MANIFEST)
    return tmp


def test_roots_cover_manifest_and_strings() -> None:
    with tempfile.TemporaryDirectory() as td:
        app_src = _tree(Path(td))
        g = graph.build(app_src)
        roots = graph.roots(g, app_src / "AndroidManifest.xml", app_src)
        assert b"Lcom/bambuna/App;" in roots
        # const-string class reference is a root (WorkManager-style reflection)
        assert b"Lcom/example/Worker;" in roots


def test_forbid_list_never_proposed() -> None:
    with tempfile.TemporaryDirectory() as td:
        app_src = _tree(Path(td))
        _g, unreach = graph.propose(app_src)
        assert b"Lcom/inmobi/Island;" in unreach  # genuinely unreachable
        assert b"Lcom/bambuna/App;" not in unreach
        assert b"Lcom/example/Worker;" not in unreach


def test_shrink_protects_first_party() -> None:
    with tempfile.TemporaryDirectory() as td:
        from patcher.patches.base import Context
        from patcher.patches.shrink import ShrinkPatch

        app_src = _tree(Path(td))
        ctx = Context(
            app_src=app_src,
            anchors_dir=app_src / "anchors",
            journal_dir=app_src / "journal",
            offline=False,
        )
        p = ShrinkPatch()
        p.approve = True
        res = p.apply(ctx)
        assert res.applied == 1, res.messages
        assert not (app_src / "smali" / "com" / "inmobi" / "Island.smali").exists()
        assert (app_src / "smali" / "com" / "bambuna" / "App.smali").exists()
        assert (app_src / "smali" / "com" / "example" / "Worker.smali").exists()


def main() -> int:
    test_roots_cover_manifest_and_strings()
    test_forbid_list_never_proposed()
    test_shrink_protects_first_party()
    print("PASS - roots and forbid-list hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
