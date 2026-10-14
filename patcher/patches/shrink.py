"""MODULE shrink -- DCE proposal (never applied by the CLI), then shim emission.

DCE runs BEFORE shims; the shim set is measured after deletion, not assumed.
Deletion is PROPOSAL-ONLY: ShrinkPatch.apply reports the proposal and writes
nothing. Shims always emit (surviving code must resolve every deleted type).
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from patcher import config, graph
from patcher.patches.base import Anchor, AnchorError, Context, Patch, PatchResult


class ShrinkPatch(Patch):
    name = "shrink"
    tier = "size"
    depends_on: tuple[str, ...] = ("ads", "telemetry")
    approve = False  # programmatic opt-in only; the CLI never sets it

    def resolve(self, ctx: Context) -> list[Anchor]:
        return [Anchor(id="dce.proposal", file="(graph)", descriptor="(computed)")]

    def apply(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        g, unreach = graph.propose(ctx.app_src)
        res.note(f"graph: {g.stats}")
        res.note(f"SET_S_BEFORE={self._set_s(ctx)}")
        # forbid-list: never delete these even if unreachable
        protected = []
        for d in unreach:
            s = d.decode()
            if s.startswith("Lcom/bambuna/"):
                protected.append(d)
                continue
            for ns in config.KEEP_TREES:
                if s.startswith("L" + ns.replace(".", "/")):
                    protected.append(d)
                    break
        protected_set = set(protected)
        candidates = [d for d in unreach if d not in protected_set]
        res.note(
            f"proposal: {len(candidates)} deletable, {len(protected)} protected by forbid-list"
        )
        if not self.approve or ctx.offline:
            res.note("[proposal only]")
            return res
        deleted = 0
        shapes: dict[str, dict] = {}
        for d in candidates:
            f = g.classes.get(d)
            if f and f.is_file():
                _record_shape(f, d.decode()[1:-1], shapes)  # capture before unlinking
                f.unlink()
                deleted += 1
        if shapes:
            self._merge_shapes(ctx, shapes)
        res.applied = deleted
        res.note(f"deleted {deleted} classes")
        return res

    def _merge_shapes(self, ctx: Context, new: dict[str, dict]) -> None:
        import json

        f = ctx.anchors_dir / "deleted_sdk_classes.json"
        cur: dict[str, dict] = {}
        if f.is_file():
            try:
                cur = json.loads(f.read_text())
            except Exception:
                cur = {}
        cur.update(new)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(cur, indent=1))

    def _set_s(self, ctx: Context) -> int:
        """Distinct ad-SDK types referenced by surviving code."""
        from patcher.inventory import survivor_ad_refs

        return len(survivor_ad_refs(ctx.app_src))

    def verify(self, ctx: Context) -> list[str]:
        g, un = graph.propose(ctx.app_src)
        prot = [d.decode() for d in un if d.startswith(b"Lcom/bambuna/")]
        out = [f"OK  graph still computes ({g.stats})"]
        if prot:
            out.append(
                f"FAIL {len(prot)} first-party classes are unreachable: " + ", ".join(prot[:5])
            )
        else:
            out.append("OK  no first-party class is unreachable")
        return out


class ShimPatch(Patch):
    """Emit stand-in classes for types our patches deleted.

    The shim set is computed: audit.py lists every referenced-but-missing
    type, restricted to config.SHIM_NAMESPACES. Correctness rules:

    * Preserve the real `.super` (from ground-truth shapes), or ART rejects
      callers that pass the instance as the supertype.
    * Interfaces stay interfaces; a class shim under `.implements` breaks
      verification.
    * Rewrite files carrying our `recast-shim` marker so stale shims heal.
    * Drop a `.super`/`.implements` that resolves nowhere.
    * A `new-instance` target is emitted as a class even if captured as an
      interface.
    """

    name = "shim"
    tier = "size"
    depends_on: tuple[str, ...] = ("shrink",)

    SHIM_MANIFEST = "shims.txt"
    MARKER = b"recast-shim"

    # invoke-<kind> {..}, Ltype;->name(args)ret
    INVOKE_RE = re.compile(
        rb"(invoke-(?:static|virtual|direct|interface|super))\s+\{[^}]*\},\s*"
        rb"((?:Lcom|Lokhttp3)/[A-Za-z0-9/_$]+(?:\$[A-Za-z0-9_$]+)?;)"
        rb"->([A-Za-z0-9_$<>]+)\(([^)]*)\)([^\s;]+;?)"
    )
    # new-instance <reg>, Ltype;    -- construction needs a class, not interface
    NEW_RE = re.compile(
        rb"new-instance\s+[vp]\d+,\s*((?:Lcom|Lokhttp3)/[A-Za-z0-9/_$]+(?:\$[A-Za-z0-9_$]+)?;)"
    )

    def _roots(self, ctx: Context) -> list:
        return [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]

    def _is_ours(self, path: Path) -> bool:
        """True when the file is one of our generated shims."""
        try:
            return self.MARKER in path.read_bytes()[:400]
        except OSError:
            return False

    def _rel(self, root: Path, path: Path) -> str:
        return str(path.relative_to(root))

    def _declared_class(self, path: Path) -> str | None:
        """The class a smali file declares in its .class header, if parseable."""
        try:
            first = path.read_bytes().split(b"\n", 1)[0]
        except OSError:
            return None
        m = re.match(rb"\.class[ \t]+(?:[^ \t\r\n]+[ \t]+)*(L[A-Za-z0-9/$_]+;)", first)
        return m.group(1).decode() if m else None

    def _exact_exists(self, path: Path) -> bool:
        """Case-exact existence (plain is_file() is case-insensitive on macOS,
        where Ej.smali and ej.smali are one file)."""
        try:
            return path.name in os.listdir(path.parent)
        except OSError:
            return False

    def _target_for(self, ctx: Context, desc: str) -> Path:
        """Write slot for desc's shim, following apktool's collision convention:
        exact name match wins, else Foo.1.smali, .2, ... ."""
        base = ctx.app_src / "smali" / (desc[1:-1] + ".smali")
        if self._exact_exists(base):
            declared = self._declared_class(base)
            if declared == desc or (self._is_ours(base) and declared != desc):
                return base  # ours to (re)write: normal rewrite or clobber repair
            stem, suffix = base.stem, base.suffix
            for n in range(1, 10):
                cand = base.with_name(f"{stem}.{n}{suffix}")
                if not self._exact_exists(cand):
                    return cand
                if self._declared_class(cand) == desc:
                    return cand
            raise AnchorError(f"shim slot exhausted for {desc}")
        parent = base.parent
        try:
            entries = os.listdir(parent)
        except OSError:
            entries = []
        lowered = base.name.lower()
        if any(e.lower() == lowered for e in entries):
            stem, suffix = base.stem, base.suffix
            for n in range(1, 10):
                cand = base.with_name(f"{stem}.{n}{suffix}")
                if cand.name in entries:
                    if self._declared_class(parent / cand.name) == desc:
                        return cand
                    continue
                return cand
            raise AnchorError(f"shim slot exhausted for {desc}")
        return base

    def _locate(self, ctx: Context, desc: str) -> Path | None:
        """The file holding `desc`: exact path plus .N collision aliases,
        trusted only if its header declares `desc`."""
        rel = desc[1:-1] + ".smali"
        stem, suffix = rel[: -len(".smali")], ".smali"
        for root in self._roots(ctx):
            for cand_rel in [rel] + [f"{stem}.{n}{suffix}" for n in range(1, 10)]:
                p = root / cand_rel
                if not self._exact_exists(p):
                    continue
                if self._declared_class(p) == desc or self._is_ours(p):
                    return p
                return p  # real survivor under its rightful name
        return None

    def _scan_refs(self, ctx: Context, wanted: set[str]) -> tuple[dict[str, set], set[str]]:
        """One tree walk collecting (methods, constructed) for `wanted`.

        methods: {desc: {(name, args, ret, is_static)}} from invoke sites.
        constructed: types survivors instantiate with new-instance (these must
        stay classes even when captured as interfaces). Our own shims are
        skipped as referrers in both.
        """
        methods: dict[str, set] = {}
        constructed: set[str] = set()
        for root in self._roots(ctx):
            for f in sorted(root.rglob("*.smali")):
                data = f.read_bytes()
                if self.MARKER in data[:400]:
                    continue
                for m in self.INVOKE_RE.finditer(data):
                    t = m.group(2).decode()
                    if t in wanted:
                        methods.setdefault(t, set()).add(
                            (
                                m.group(3).decode(),
                                m.group(4).decode(),
                                m.group(5).decode(),
                                m.group(1) == b"invoke-static",
                            )
                        )
                for m in self.NEW_RE.finditer(data):
                    if m.group(1).decode() in wanted:
                        constructed.add(m.group(1).decode())
        return methods, constructed

    def _shapes(self, ctx: Context, needed: set[str] | None = None) -> dict:
        """Ground-truth shapes from patcher/shapes.py, optionally refilling
        `needed` entries from the source APK."""
        from patcher import shapes

        return shapes.capture(ctx, needed)

    def _resolvable(self, ctx: Context) -> set[str]:
        present: set[str] = set()
        for root in self._roots(ctx):
            for f in root.rglob("*.smali"):
                present.add(config.descriptor_for(root, f))
        return present

    def _recorded_shim_descs(self, ctx: Context) -> set[str]:
        """Descriptors of shims already on record (shim manifest)."""
        out: set[str] = set()
        manifest = ctx.anchors_dir / self.SHIM_MANIFEST
        if manifest.is_file():
            for ln in manifest.read_text().splitlines():
                if ln.endswith(".smali") and "/" in ln:
                    stemmed = config.strip_collision_suffix(ln[: -len(".smali")].split("/", 1)[1])
                    out.add("L" + stemmed + ";")
        return out

    def apply(self, ctx: Context) -> PatchResult:
        from patcher import audit

        res = PatchResult()
        # The shim set: everything referenced by surviving code that resolves
        # nowhere, restricted to namespaces we delete.
        a = audit.run(ctx.app_src)
        needed: set[str] = set(a["needs_shim"])
        res.note(f"dangling refs needing a shim: {len(needed)}")
        if ctx.offline:
            res.note("[dry-run] would emit shims")
            return res
        shapes = self._shapes(ctx, needed | self._recorded_shim_descs(ctx))
        # Expand the shape request over supertypes/interfaces BEFORE the closure
        # runs: the closure can only follow edges present in `shapes`, and the
        # first fetch covers only directly-referenced types. Without this, a
        # chain like b -> l0 -> AppLovinWebViewBase -> WebView stops at b (l0
        # was never requested), b's super drops to Object, and ART rejects the
        # class at launch (the j75 VerifyError). Batch-fetch the frontier until
        # it closes; the full-universe cache makes repeat fetches cheap.
        _fetchable = tuple("L" + ns + "/" for ns in config.SHIM_NAMESPACES)
        wanted = set(needed) | self._recorded_shim_descs(ctx)
        for _ in range(6):
            frontier = set()
            for _d in wanted:
                _shp = shapes.get(_d, {})
                _sup = _shp.get("super")
                if (
                    isinstance(_sup, str)
                    and _sup.startswith("L")
                    and _sup not in shapes
                    and _sup not in wanted
                    and _sup.startswith(_fetchable)
                ):
                    frontier.add(_sup)
                _impls = _shp.get("implements") or []
                if isinstance(_impls, str):
                    _impls = [_impls]
                for _v in _impls:
                    if (
                        _v.startswith("L")
                        and _v not in shapes
                        and _v not in wanted
                        and _v.startswith(_fetchable)
                    ):
                        frontier.add(_v)
            if not frontier:
                break
            wanted |= frontier
            shapes = self._shapes(ctx, wanted)
        present = self._resolvable(ctx)
        recorded = self._recorded_shim_descs(ctx)
        # Re-emit our shims whose kind or .super contradicts ground truth
        # (they resolve, so the audit never names them).
        emit: set[str] = set(needed)
        for desc in recorded:
            if desc in emit:
                continue
            loc = self._locate(ctx, desc)
            if loc is None or not self._is_ours(loc):
                continue
            try:
                head = loc.read_bytes()[:400]
            except OSError:
                continue
            first = head.split(b"\n")[0]
            want_iface = bool(shapes.get(desc, {}).get("is_interface"))
            got_iface = b"interface" in first
            if want_iface != got_iface:
                emit.add(desc)
                continue
            if not want_iface:
                m = re.search(rb"^\.super (\S+)", head, re.MULTILINE)
                want_super = shapes.get(desc, {}).get("super")
                # A known shape means shimmable, pulling the chain into emit.
                if (
                    m
                    and want_super
                    and m.group(1).decode() != want_super
                    and (
                        want_super in present
                        or want_super in recorded
                        or want_super in emit
                        or want_super in shapes
                    )
                ):
                    emit.add(desc)
        if len(emit) != len(needed):
            res.note(f"interface/class mismatches to heal: {len(emit) - len(needed)}")

        def shape_for(desc: str) -> dict:
            return shapes.get(desc, {})

        def _iface_closure(desc: str) -> set[str]:
            seen: set[str] = set()
            stack = [desc]
            while stack:
                cur = stack.pop()
                shp = shape_for(cur)
                impls = shp.get("implements") or []
                if isinstance(impls, str):
                    impls = [impls]
                for i in impls:
                    if i not in seen:
                        seen.add(i)
                        stack.append(i)
            return seen

        # Interfaces are invoked on the interface type, never on our impls, so
        # scan for emit + reachable interfaces in one walk.
        wanted_ifaces: set[str] = set()
        for _d in emit | recorded:
            wanted_ifaces |= _iface_closure(_d)
        methods, constructed = self._scan_refs(ctx, set(emit) | wanted_ifaces)

        fw = (
            "Landroid/",
            "Landroidx/",
            "Lkotlin/",
            "Lkotlinx/",
            "Ljava/",
            "Ljavax/",
            # No broad gms/ entry: gms/ads and gms/ump are deleted.
            "Lcom/google/android/gms/auth/",
            "Ldalvik/",
            "Lorg/apache/",
            "Lorg/json/",
            "Lorg/w3c/",
            "Lorg/xml/",
            "Lcom/google/api/",
            "Lcom/google/common/",
        )

        # Deleted namespaces are never framework-resolvable.
        _deleted = tuple("L" + ns + "/" for ns in config.SHIM_NAMESPACES)

        def ok(t: str) -> bool:
            # Post-run aware: resolvable means present now or emitted this run.
            if t in present or t in emit:
                return True
            if t.startswith(_deleted):
                return False
            return t.startswith(fw)

        # Pull in supertypes/interfaces the shims need but nobody references.
        pending = set(emit)
        while pending:
            desc = pending.pop()
            shp = shape_for(desc)
            for key in ("super", "implements"):
                vals = shp.get(key) or []
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    if not (v and v.startswith("L")):
                        continue
                    if v in present or v.startswith(fw):
                        continue
                    if v in emit:
                        continue
                    if v in shapes and not ok(v):
                        emit.add(v)
                        methods.setdefault(v, set())
                        pending.add(v)

        written: list[str] = []
        emitted = rewritten = 0

        # Class shims must concretely implement every method of every
        # interface they (transitively) implement; methods are only recorded
        # where they are invoked, so interface-invoked methods are propagated
        # to implementors here (already scanned above).
        for desc in sorted(emit):
            if shape_for(desc).get("is_interface"):
                continue
            have = {(m, a, r) for (m, a, r, _s) in methods.get(desc, set())}
            extra: set[tuple[str, str, str, bool]] = set()
            for iface in _iface_closure(desc):
                for mname, args, ret, _s in methods.get(iface, set()):
                    if mname != "<init>" and (mname, args, ret) not in have:
                        extra.add((mname, args, ret, False))
                        have.add((mname, args, ret))
            if extra:
                methods.setdefault(desc, set()).update(extra)
        # Heal class shims missing interface methods computed above.
        healed_iface = 0
        for desc in sorted(recorded - emit):
            if shape_for(desc).get("is_interface"):
                continue
            loc = self._locate(ctx, desc)
            if loc is None or not self._is_ours(loc):
                continue
            try:
                text = loc.read_text()
            except OSError:
                continue
            file_sigs = set(
                re.findall(
                    r"^\.method\s+\S+(?:\s+\S+)?\s+(\S+?)\(([^)]*)\)(\S+)", text, re.MULTILINE
                )
            )
            need = {
                (m, a, r)
                for iface in _iface_closure(desc)
                for (m, a, r, _s) in methods.get(iface, set())
                if m != "<init>"
            }
            if need - file_sigs:
                emit.add(desc)
                healed_iface += 1
                for m, a, r in sorted(need):
                    if (m, a, r) not in {(x, y, z) for (x, y, z, _w) in methods.get(desc, set())}:
                        methods.setdefault(desc, set()).add((m, a, r, False))
        if healed_iface:
            res.note(f"interface-method gaps healed: {healed_iface}")
        for desc in sorted(emit):
            existing = self._locate(ctx, desc)
            if existing is not None and not self._is_ours(existing):
                # a real survivor (shadow / app code) -- record, never touch
                roots = [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]
                for root in roots:
                    p = root / (desc[1:-1] + ".smali")
                    if p.is_file():
                        written.append(self._rel(root, p))
                        break
                continue
            target = self._target_for(ctx, desc)
            target.parent.mkdir(parents=True, exist_ok=True)
            was_ours = existing is not None
            target.write_text(
                self._shim_source(desc, methods.get(desc, set()), shape_for(desc), constructed, ok)
            )
            written.append(str(target.relative_to(ctx.app_src)))
            if was_ours:
                rewritten += 1
            else:
                emitted += 1

        ctx.anchors_dir.mkdir(parents=True, exist_ok=True)
        # Drop orphan shims: ours iff at their descriptor's rightful path.
        collected = 0
        for root in self._roots(ctx):
            for ns in config.SHIM_NAMESPACES:
                nsdir = root / ns
                if not nsdir.is_dir():
                    continue
                for f in sorted(nsdir.rglob("*.smali")):
                    if not self._is_ours(f):
                        continue
                    declared = self._declared_class(f)
                    try:
                        owned = declared is not None and self._target_for(ctx, declared) == f
                    except AnchorError:
                        owned = False
                    if not owned:
                        f.unlink()
                        collected += 1
        if collected:
            res.note(f"collected {collected} orphan shim(s)")
        # Manifest lists every shim on disk; ads.verify() excludes these from
        # surviving-SDK counts.
        on_disk = {
            str(f.relative_to(ctx.app_src))
            for ns in config.SHIM_NAMESPACES
            for root in self._roots(ctx)
            for f in (root / ns).rglob("*.smali")
            if self._is_ours(f)
        }
        full = set(written) | on_disk
        (ctx.anchors_dir / self.SHIM_MANIFEST).write_text("\n".join(sorted(full)))
        res.applied = emitted + rewritten
        res.note(
            f"shims: {emitted} new, {rewritten} rewritten from stale; "
            f"manifest holds {len(full)} entries"
        )
        return res

    def _zero_for(self, ret: str) -> str:
        """Body returning the zero value. Every branch declares .locals: smali
        requires a register directive on any non-abstract method."""
        if ret == "V":
            return ".locals 0\n    return-void"
        if ret in ("Z", "B", "C", "I", "S", "F"):
            return ".locals 1\n    const/4 v0, 0x0\n    return v0"
        if ret in ("J", "D"):
            return ".locals 2\n    const-wide v0, 0x0\n    return-wide v0"
        return ".locals 1\n    const/4 v0, 0x0\n    return-object v0"

    def _shim_source(
        self,
        desc: str,
        methods: set[tuple[str, str, str, bool]],
        shape: dict | None = None,
        constructed: set[str] | None = None,
        ok: Callable[[str], bool] | None = None,
    ) -> str:
        shape = shape or {}
        cls = desc[1:-1]  # Lcom/a/B; -> com/a/B
        _path, _, _name = cls.replace("/", ".").rpartition(".")
        # An interface stays an interface unless survivors construct it.
        as_interface = shape.get("is_interface") and desc not in (constructed or set())
        out = [
            # desc already carries its trailing semicolon ("Lcom/a/B;")
            f".class public {'interface abstract ' if as_interface else ''}{desc}",
            f".super {shape.get('super') or 'Ljava/lang/Object;'}",
            '.source "recast-shim"',
            "",
            "# shim emitted by the RecastAddict patcher for a removed ad-SDK type.",
        ]
        if as_interface:
            out.append("# interface shim: satisfies .implements clauses.")
        else:
            sup = shape.get("super") or "Ljava/lang/Object;"
            out.append(f"# captured superclass ({sup}).")
        # Drop a super/interface that resolves nowhere.
        impls = [i for i in (shape.get("implements") or []) if ok is None or ok(i)]
        sup = shape.get("super") or "Ljava/lang/Object;"
        if ok is not None and not ok(sup):
            out[1] = ".super Ljava/lang/Object;"
            sup = "Ljava/lang/Object;"

        if as_interface:
            for i in impls:
                out.append(f".implements {i}")
            out.append("")
            seen: set[tuple[str, str, str]] = set()
            for mname, args, ret, _s in sorted(methods):
                if mname == "<init>":
                    continue
                if (mname, args, ret) in seen:
                    continue
                seen.add((mname, args, ret))
                out += [f".method public abstract {mname}({args}){ret}", ".end method", ""]
            return "\n".join(out) + "\n"

        for i in impls:
            out.append(f".implements {i}")
        out += [
            "",
            "# constructors forward a Context to super when one is present.",
        ]
        if sup == "Ljava/lang/Object;":
            out += [
                ".method public constructor <init>()V",
                "    .locals 0",
                "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V",
                "    return-void",
                ".end method",
                "",
            ]
            ctors: list[tuple[str, str]] = []
        else:
            canonical = [
                ("Landroid/content/Context;", "Landroid/content/Context;"),
                (
                    "Landroid/content/Context;Landroid/util/AttributeSet;",
                    "Landroid/content/Context;Landroid/util/AttributeSet;",
                ),
            ]
            ctors = sorted({(a, "V") for (n, a, _r, _s) in methods if n == "<init>" and a})
            for sig, real in canonical:
                if sig not in [a for a, _ in ctors]:
                    ctors.append((sig, real))
        for args, _ret in ctors:
            if args in (
                "Landroid/content/Context;",
                "Landroid/content/Context;Landroid/util/AttributeSet;",
            ):
                super_args, super_reg = args, "p1"
            elif "Landroid/content/Context;" in args:
                super_args = "Landroid/content/Context;"
                super_reg = f"p{_param_index_of(args, 'Landroid/content/Context;')}"
            else:
                super_args, super_reg = "", "p0"
            out += [
                f".method public constructor <init>({args})V",
                f"    .locals {_reg_count(args) + 2}",
                f"    invoke-direct {{{super_reg}}}, {sup}-><init>({super_args})V",
                "    return-void",
                ".end method",
                "",
            ]
        # Dedupe by (name, args, ret); smali rejects duplicate methods.
        dedup: dict[tuple[str, str, str], bool] = {}
        for mname, args, ret, is_static in sorted(methods):
            if mname == "<init>":
                continue
            dedup[(mname, args, ret)] = dedup.get((mname, args, ret), False) or is_static
        for (mname, args, ret), is_static in sorted(dedup.items()):
            mod = "public static" if is_static else "public"
            out += [
                f".method {mod} {mname}({args}){ret}",
                "    " + self._zero_for(ret),
                ".end method",
                "",
            ]
        return "\n".join(out) + "\n"

    def resolve(self, ctx: Context) -> list[Anchor]:
        return [Anchor(id="shim.set_s", file="(computed)", descriptor="(computed)")]

    def verify(self, ctx: Context) -> list[str]:
        from patcher import audit

        manifest = ctx.anchors_dir / self.SHIM_MANIFEST
        if not manifest.is_file():
            return ["FAIL shim manifest missing (run patch shim)"]
        emitted = [line for line in manifest.read_text().splitlines() if line]
        a = audit.run(ctx.app_src)
        needed: set[str] = set(a["needs_shim"])
        missing = sorted(d for d in needed if self._locate(ctx, d) is None)
        gone = [rel for rel in emitted if not (ctx.app_src / rel).is_file()]
        out = [f"OK  {len(emitted)} shims on record; {len(needed)} dangling refs to cover"]
        if missing:
            out.append(f"FAIL {len(missing)} dangling refs lack a shim: " + ", ".join(missing[:6]))
        else:
            out.append("OK  every dangling ref in a deleted namespace resolves to a file")
        if gone:
            out.append(
                f"FAIL {len(gone)} manifest entries no longer exist on disk "
                f"(re-run `patch shim`): " + ", ".join(gone[:4])
            )
        else:
            out.append("OK  manifest agrees with the tree")
        out += _audit_shim_hierarchy(ctx, emitted)
        out += _audit_shim_supers(ctx, emitted)
        return out


def _record_shape(path: Path, desc: str, out: dict[str, dict]) -> None:
    """Record .class/.super/.implements for a class about to be deleted."""
    try:
        sup, impls = "Ljava/lang/Object;", []
        is_interface = False
        for line in path.read_text(errors="ignore").splitlines():
            t = line.strip()
            if t.startswith(".class "):
                is_interface = " interface " in f" {t} "
            elif t.startswith(".super "):
                sup = t.split(None, 1)[1].strip()
            elif t.startswith(".implements "):
                impls.append(t.split(None, 1)[1].strip())
        out["L" + desc + ";"] = {"super": sup, "implements": impls, "is_interface": is_interface}
    except Exception:  # nosec B110 -- unreadable-file guard
        pass


def _reg_count(descr_args: str) -> int:
    """Number of 4-byte registers a descriptor's parameter list occupies."""
    n = 0
    i = 0
    while i < len(descr_args):
        c = descr_args[i]
        if c == "L":
            i = descr_args.index(";", i) + 1
            n += 1
        elif c == "[":
            i += 1
            while i < len(descr_args) and descr_args[i] == "[":
                i += 1
            if i < len(descr_args) and descr_args[i] == "L":
                i = descr_args.index(";", i) + 1
            else:
                i += 1
            n += 1
        else:
            n += 2 if c in "JD" else 1
            i += 1
    return n


def _param_index_of(args: str, want: str) -> int:
    """Parameter register index (p0 is `this`) at which `want` sits in `args`.

    Register number = 1 (for `this`) + the wide-word offset of that parameter,
    since J/D occupy two registers.
    """
    idx, i = 0, 0
    while i < len(args):
        if args.startswith(want, i):
            return 1 + idx
        c = args[i]
        if c == "L":
            j = args.index(";", i) + 1
            step, i = 1, j
        elif c == "[":
            while i < len(args) and args[i] == "[":
                i += 1
            if i < len(args) and args[i] == "L":
                i = args.index(";", i) + 1
            else:
                i += 1
            step = 1
        else:
            step, i = (2 if c in "JD" else 1), i + 1
        idx += step
    return 1 + idx


def _audit_shim_hierarchy(ctx: Context, manifest_rel: list[str]) -> list[str]:
    """Every shim's .super/.implements must resolve to a file or framework."""
    import re

    roots = [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]
    present: set[str] = set()
    for r in roots:
        for f in r.rglob("*.smali"):
            present.add(config.descriptor_for(r, f))
    fw = tuple(
        "L" + ns + "/"
        for ns in (
            "java",
            "javax",
            "javax/crypto",
            "javax/net",
            "javax/security",
            "android",
            "androidx",
            "kotlin",
            "kotlinx",
            "dalvik",
            "org/apache",
            "org/json",
            "org/w3c",
            "org/xml",
            # NOTE: no "com/google/android/gms" -- gms/ads is deleted, so a
            # shim .super/.implements under gms/* must resolve to a file, never
            # to a presumed framework class (cf. the ok() fix in apply()).
            "com/google/android/gms/auth",
            "com/google/api",
            "com/google/common",
        )
    )
    _deleted = tuple("L" + ns + "/" for ns in config.SHIM_NAMESPACES)
    bad: list[str] = []
    skipped = 0
    for rel in manifest_rel:
        # rels are app_src-relative ("smali/..."), not dex-root-relative.
        p = ctx.app_src / rel
        if not p.is_file():
            skipped += 1
            continue
        src = p.read_text()
        super_names = re.findall(r"^\.super (L[A-Za-z0-9/$_]+;)", src, re.MULTILINE)
        impl_names = re.findall(r"^\.implements (L[A-Za-z0-9/$_]+;)", src, re.MULTILINE)
        for kind, names in (("super", super_names), ("implements", impl_names)):
            for n in names:
                if n in present:
                    continue
                # Deleted namespaces are never framework-resolvable (see ok()).
                if n.startswith(_deleted) or not n.startswith(fw):
                    bad.append(f"{rel} {kind} {n}")
    if bad:
        return [
            f"FAIL {len(bad)} shim super/interface types resolve nowhere: " + ", ".join(bad[:4])
        ]
    suffix = f" ({skipped} manifest entries missing from disk)" if skipped else ""
    return [f"OK  shim hierarchy resolves ({len(manifest_rel)} classes audited){suffix}"]


def _audit_shim_supers(ctx: Context, manifest_rel: list[str]) -> list[str]:
    """Every class-shim's .super matches ground truth when it resolves."""
    import json
    import re

    from patcher import config as _config

    cache = ctx.anchors_dir / "deleted_sdk_classes.json"
    try:
        shapes: dict = json.loads(cache.read_text())
    except Exception:
        return ["WARN  shape cache unreadable -- super-conformance unchecked"]
    present: set[str] = set()
    for root in sorted(ctx.app_src.glob("smali*")):
        if root.is_dir():
            for f in root.rglob("*.smali"):
                present.add(_config.descriptor_for(root, f))
    bad: list[str] = []
    checked = 0
    for rel in manifest_rel:
        p = ctx.app_src / rel
        if not p.is_file():
            continue
        try:
            head = p.read_text()[:400]
        except OSError:
            continue
        if "recast-shim" not in head:
            continue
        if " interface " in head.split("\n")[0]:
            continue
        m = re.search(r"^\.super (\S+)", head, re.MULTILINE)
        if not m:
            continue
        desc = "L" + _config.strip_collision_suffix(rel.split("/", 1)[1][: -len(".smali")]) + ";"
        want = shapes.get(desc, {}).get("super")
        if not want or want == "Ljava/lang/Object;":
            continue
        checked += 1
        if want in present and m.group(1) != want:
            bad.append(f"{rel} super {m.group(1)} != {want}")
    if bad:
        return [f"FAIL {len(bad)} shims drop a resolvable superclass: " + ", ".join(bad[:4])]
    return [f"OK  shim supers conform to ground truth ({checked} checked)"]
