"""Forward reachability over the three dex roots as one codebase.

Proposal only, never a deletion authority: static reachability is unsound for
Android (reflection, JNI, class-name strings), so the output is candidates for
review and runtime testing. Converges in one pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from patcher import config
from patcher.manifest import Manifest

# Segments are optional: R8 relocates most app classes into the root package.
TYPE_RE = re.compile(rb"L[A-Za-z][A-Za-z0-9_$]*(?:/[A-Za-z0-9_$]+)*;")
STRING_TYPE_RE = re.compile(
    rb'const-string [vp]\d+, "((?:[a-z][a-zA-Z0-9_$]*\.)+[A-Z][A-Za-z0-9_$]*)"'
)
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass
class Graph:
    classes: dict[bytes, Path] = field(default_factory=dict)
    edges: dict[Path, set[bytes]] = field(default_factory=dict)
    reachable: set[bytes] = field(default_factory=set)
    unreachable: list[bytes] = field(default_factory=list)

    @property
    def stats(self) -> dict:
        return {
            "classes": len(self.classes),
            "reachable": len(self.reachable),
            "unreachable": len(self.unreachable),
        }


def _descriptor(path: Path, roots: list[Path]) -> bytes:
    for root in roots:
        try:
            path.relative_to(root)
        except ValueError:
            continue
        # descriptor_for strips apktool's case-collision suffix.
        return b"L" + config.descriptor_for(root, path)[1:-1].encode() + b";"
    return b""


def build(app_src: Path | None = None) -> Graph:
    app_src = Path(app_src or config.APP_SRC)
    roots = [p for p in sorted(app_src.glob("smali*")) if p.is_dir()]
    files = sorted(app_src.rglob("*.smali"))
    g = Graph()
    for f in files:
        d = _descriptor(f, roots)
        if d:
            g.classes[d] = f
    for f in files:
        g.edges[f] = set(TYPE_RE.findall(f.read_bytes()))
    return g


def roots(g: Graph, manifest_path: Path, app_src: Path) -> set[bytes]:
    """The PROPOSED expanded root set (see PLAN 7.5)."""
    out: set[bytes] = set()
    m = Manifest.load(manifest_path)
    pkg = m.root.get("package", "")
    for el in m.root.iter("application"):
        name = el.get(f"{ANDROID_NS}name", "")
        if name:
            full = pkg + name if name.startswith(".") else name
            out.add(b"L" + full.replace(".", "/").encode() + b";")
    pkg = m.root.get("package", "")
    for c in m.components():
        if c.name:
            # manifest names may be relative -- resolve against the package.
            full = pkg + c.name if c.name.startswith(".") else c.name
            out.add(b"L" + full.replace(".", "/").encode() + b";")

    svc_dir = app_src / "unknown" / "META-INF" / "services"
    if svc_dir.is_dir():
        for svc in svc_dir.glob("*"):
            for raw in svc.read_text(errors="ignore").split():
                line = raw.strip()
                if line and line[0].isalpha():
                    out.add(b"L" + line.replace(".", "/").encode() + b";")

    for f in app_src.rglob("*.smali"):
        for mm in STRING_TYPE_RE.finditer(f.read_bytes()):
            out.add(b"L" + mm.group(1).replace(b".", b"/") + b";")

    for ns in config.KEEP_TREES:
        prefix = b"L" + ns.replace(".", "/").encode()
        out |= {d for d in g.classes if d.startswith(prefix)}
    out |= {d for d in g.classes if d.startswith(b"Lcom/bambuna/")}
    return {d for d in out if d in g.classes}


def reach(g: Graph, root_set: set[bytes]) -> set[bytes]:
    """One forward pass. Iteration is a provable no-op -- see module docstring."""
    seen: set[bytes] = set()
    stack = [d for d in root_set if d in g.classes]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        f = g.classes.get(cur)
        if f is None:
            continue
        for dep in g.edges.get(f, ()):
            if dep in g.classes and dep not in seen:
                stack.append(dep)
    return seen


def propose(app_src: Path | None = None) -> tuple[Graph, list[bytes]]:
    app_src = Path(app_src or config.APP_SRC)
    g = build(app_src)
    g.reachable = reach(g, roots(g, app_src / "AndroidManifest.xml", app_src))
    g.unreachable = sorted(set(g.classes) - g.reachable)
    return g, g.unreachable
