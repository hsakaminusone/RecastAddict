"""Smali layer: parse -> serialize is byte-identical, stubs are idempotent."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from patcher.smali.editor import is_stub, stub_method
from patcher.smali.reader import SmaliFile
from patcher.smali.span import find_method_spans, serialize

DEFAULT_APP_SRC = Path(__file__).resolve().parents[2] / "app_src"

SAMPLE = """\
.class public La51;
.super Ljava/lang/Object;
.source "y31.java"

.method public static f()Z
    .locals 2
    sget-object v0, Lzh;->b:Z
    return v0
.end method

.method public static declared-synchronized g(Landroid/content/Context;)Z
    .locals 2
    sget-boolean v0, Lz9;->a:Z
    if-eqz v0, :no
    const/4 v0, 0x1
    return v0
    :no
    const/4 v0, 0x0
    return v0
.end method
"""


def _write(tmp: Path) -> Path:
    p = tmp / "smali" / "a51.smali"
    p.parent.mkdir(parents=True)
    p.write_text(SAMPLE)
    return p


def roundtrip_tree(app_src: Path = DEFAULT_APP_SRC) -> tuple[int, int, list[str]]:
    files = sorted(Path(app_src).rglob("*.smali"))
    failures: list[str] = []
    total_methods = 0
    for f in files:
        data = f.read_bytes()
        try:
            spans = find_method_spans(data, f)
            total_methods += len(spans)
            expected = sum(1 for line in data.split(b"\n") if line.startswith(b".method"))
            if len(spans) != expected:
                failures.append(f"{f}: span count {len(spans)} != .method lines {expected}")
                continue
            if serialize(data, spans) != data:
                failures.append(f"{f}: round-trip not byte-identical")
        except Exception as exc:
            failures.append(f"{f}: {type(exc).__name__}: {exc}")
    return len(files), total_methods, failures


def test_smali_roundtrip() -> None:
    if not DEFAULT_APP_SRC.is_dir():
        print("SKIP: app_src not decoded")
        return
    _, _, failures = roundtrip_tree()
    assert not failures, f"{len(failures)} files failed round-trip:\n" + "\n".join(failures[:10])


def test_stub_preserves_header() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = _write(Path(td))
        sf = SmaliFile(p)
        before = sf.find("f", "()Z")
        assert before is not None
        edit = stub_method(sf, "f", "()Z", reason="test")
        assert edit is not None
        assert edit.new_bytes.startswith(edit.old_bytes[: before.body_start])
        assert b".method public static f()Z\n" in edit.new_bytes


def test_stub_is_idempotent() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = _write(Path(td))
        sf = SmaliFile(p)
        edit = stub_method(sf, "f", "()Z", reason="test")
        assert edit is not None
        p.write_bytes(edit.new_bytes)
        sf2 = SmaliFile(p)
        assert stub_method(sf2, "f", "()Z", reason="test") is None
        span = sf2.find("f", "()Z")
        assert span is not None and is_stub(sf2.data, span, "Z", 1)


def test_stub_false_value() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = _write(Path(td))
        sf = SmaliFile(p)
        edit = stub_method(sf, "g", "(Landroid/content/Context;)Z", reason="test", value=0)
        assert edit is not None
        assert b"const/4 v0, 0x0" in edit.new_bytes
        assert b"declared-synchronized" in edit.new_bytes


def test_stub_missing_fails_loud() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = _write(Path(td))
        sf = SmaliFile(p)
        try:
            stub_method(sf, "nope", "()Z", reason="test")
        except KeyError:
            return
        raise AssertionError("stubbing a missing method must raise KeyError")


def main() -> int:
    test_smali_roundtrip()
    test_stub_preserves_header()
    test_stub_is_idempotent()
    test_stub_false_value()
    test_stub_missing_fails_loud()
    print("PASS - smali round-trip byte-identical, stubs idempotent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
