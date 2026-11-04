"""AndroidManifest model and dependency-aware component removal.

Uses ElementTree, never regex over lines: attributes can be reordered, quoted
differently, or split across lines, and reacting to a manifest with pattern
matching is how you produce a broken APK.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # nosec B405 -- local apktool output
from dataclasses import dataclass
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"
REMOVABLE_TAGS = ("activity", "service", "receiver", "provider", "activity-alias")


@dataclass
class Component:
    tag: str
    name: str
    parent: Path
    exported: bool | None = None


@dataclass
class Manifest:
    path: Path
    tree: ET.ElementTree[ET.Element[str]]
    root: ET.Element[str]

    @classmethod
    def load(cls, path: Path) -> Manifest:
        tree = ET.parse(path)  # noqa: S314  # nosec B314 -- local apktool output
        return cls(path=Path(path), tree=tree, root=tree.getroot())

    # ------------------------------------------------------------------ query
    def components(self) -> list[Component]:
        out = []
        for tag in REMOVABLE_TAGS:
            for el in self.root.iter(tag):
                name = el.get(f"{ANDROID}name", "")
                exp = el.get(f"{ANDROID}exported")
                out.append(
                    Component(
                        tag=tag,
                        name=name,
                        parent=self.path,
                        exported=None if exp is None else exp == "true",
                    )
                )
        return out

    def meta_datas(self) -> list[tuple[str, ET.Element]]:
        return [(el.get(f"{ANDROID}name", ""), el) for el in self.root.iter("meta-data")]

    def providers(self) -> list[Component]:
        return [c for c in self.components() if c.tag == "provider"]

    def names_matching(self, predicates: list[str]) -> list[Component]:
        """Components whose android:name starts with any of the given prefixes."""
        return [c for c in self.components() if any(c.name.startswith(p) for p in predicates)]

    # ----------------------------------------------------------------- remove
    def remove(self, comp: Component) -> bool:
        """Remove a component element (and an empty parent <application>)."""
        for el in self.root.iter():
            for child in list(el):
                if child.tag == comp.tag and child.get(f"{ANDROID}name") == comp.name:
                    el.remove(child)
                    return True
        return False

    def remove_meta_data(self, name: str) -> bool:
        for parent in self.root.iter():
            for child in list(parent):
                if child.tag == "meta-data" and child.get(f"{ANDROID}name") == name:
                    parent.remove(child)
                    return True
        return False

    def remove_elements(self, tag: str, names: tuple[str, ...]) -> int:
        """Remove every `tag` element (e.g. uses-permission) named in `names`."""
        cut = 0
        for parent in self.root.iter():
            for child in list(parent):
                if child.tag == tag and child.get(f"{ANDROID}name") in names:
                    parent.remove(child)
                    cut += 1
        return cut

    def save(self) -> None:
        self.tree.write(self.path, encoding="utf-8", xml_declaration=True)

    # -------------------------------------------------------------- integrity
    def check(self) -> list[str]:
        """Semantic checks that go beyond XML well-formedness."""
        problems: list[str] = []
        # components with intent-filters must declare android:exported on API 31+
        for el in self.root.iter():
            if el.tag not in REMOVABLE_TAGS:
                continue
            if el.find("intent-filter") is not None and el.get(f"{ANDROID}exported") is None:
                problems.append(
                    f"component {el.get(f'{ANDROID}name')} "
                    "has intent-filter but no android:exported"
                )
        # duplicate provider authorities
        seen: dict[str, str] = {}
        for c in self.providers():
            for el in self.root.iter("provider"):
                if el.get(f"{ANDROID}name") != c.name:
                    continue
                auth = el.get(f"{ANDROID}authorities", "")
                if auth in seen:
                    problems.append(f"duplicate provider authority {auth} ({seen[auth]}, {c.name})")
                seen[auth] = c.name
        # meta-data referencing classes that no longer exist is checked by the caller
        return problems
