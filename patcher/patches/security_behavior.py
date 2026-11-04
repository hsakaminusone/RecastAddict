"""MODULE security_behavior -- signature/installer predicate neutralisation."""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import TYPE_CHECKING

from patcher import anchors as A
from patcher import config
from patcher.manifest import Manifest
from patcher.patches.base import Anchor, AnchorError, Context, Patch, PatchResult
from patcher.patches.shrink import ShimPatch
from patcher.smali.editor import apply_edits, stub_method
from patcher.smali.reader import SmaliFile

if TYPE_CHECKING:  # annotation only; no runtime import to avoid a cycle
    from patcher.smali.span import SmaliMethodSpan

# signature-verification API surfaces swept for allowlist comparison.
SIG_PATTERNS = [
    rb"GET_SIGNATURES",
    rb"getSigningInfo",
    rb"checkSignatures",
    rb"GET_SIGNING_CERTIFICATES",
    rb"Landroid/content/pm/Signature;",
    rb"Landroid/content/pm/PackageInfo;->signatures",
    rb"Landroid/content/pm/PackageInfo;->signingInfo",
    rb"Ljava/security/cert/X509Certificate;",
    rb"Ljava/security/MessageDigest;",
    rb"getInstallerPackageName",
]
# desugar shims are API backports, not tamper detection -- must not be touched
SYNTHETIC_OK = ("xi3", "u5")


class SecurityBehaviorPatch(Patch):
    name = "security_behavior"
    tier = "behaviour"
    ordered_after = ("premium",)

    def resolve(self, ctx: Context) -> list[Anchor]:
        # installer f()/g() are stubbed by premium; found by evidence, not name.
        try:
            r = A.resolve_class(ctx.app_src, "installer_gate")
        except AnchorError as exc:
            raise AnchorError(f"security_behavior: {exc}") from exc
        return [
            Anchor(
                id="installer.f",
                file=r.rel,
                descriptor="()Z",
                method=A.class_role_name(ctx.app_src, "installer_gate", "iap_can_use"),
            ),
            Anchor(
                id="installer.g",
                file=r.rel,
                descriptor="(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z",
                method=A.class_role_name(ctx.app_src, "installer_gate", "cert_allowlist"),
            ),
        ]

    def apply(self, ctx: Context) -> PatchResult:
        # No edits here; reports the sweep so a 0/0 result is not a failure.
        sweep = self.verify(ctx)
        warns = [line for line in sweep if line.startswith("WARN")]
        return PatchResult(
            applied=len(warns),
            already=0,
            messages=[f"signature sweep: {len(warns)} site(s) reported", *warns[:3]],
        )

    def verify(self, ctx: Context) -> list[str]:
        out: list[str] = []
        try:
            r = A.resolve_class(ctx.app_src, "installer_gate")
        except AnchorError:
            out.append("FAIL installer-gate class not resolvable by evidence")
            r = None
        if r is not None:
            f_name = A.class_role_name(ctx.app_src, "installer_gate", "iap_can_use")
            g_name = A.class_role_name(ctx.app_src, "installer_gate", "cert_allowlist")
            if f_name is None or g_name is None:
                out.append("FAIL installer-gate roles unmapped in this build")
                f_name, g_name = "", ""
            targets = (
                (r.rel, f_name, "()Z"),
                (
                    r.rel,
                    g_name,
                    "(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z",
                ),
            )
            from patcher.smali.editor import is_stub

            for rel, method, desc in targets:
                sf = SmaliFile(ctx.app_src / rel)
                span = sf.find(method, desc)
                ret = desc[desc.index(")") + 1 :]
                out.append(
                    f"{'OK ' if span and is_stub(sf.data, span, ret) else 'FAIL'} "
                    f"{rel} {method}{desc} neutralised"
                )

        hits: dict[str, list[str]] = {}
        for f in sorted(ctx.app_src.rglob("*.smali")):
            if f.stem in SYNTHETIC_OK and "/com/" not in f.as_posix():
                continue
            data = f.read_bytes()
            for pat in SIG_PATTERNS:
                if re.search(pat, data):
                    key = pat.decode().replace("\\", "")
                    hits.setdefault(key, []).append(str(f.relative_to(ctx.app_src)))
        for sig, files in hits.items():
            preview = ", ".join(files[:4]) + (" ..." if len(files) > 4 else "")
            out.append(f"WARN signature API present -> {sig}: {len(files)} file(s) [{preview}]")
        if not hits:
            out.append("OK  no signature-verification API references anywhere")
        return out


AD_MANIFEST_PREFIXES = [
    "com.applovin.",
    "com.fyber.",
    "com.inmobi.",
    "com.pubmatic.",
    "com.google.android.gms.ads",
    "com.google.android.ump",
    "com.amazon.aps",
    "com.amazon.device.ads",
]
AD_META_KEYS = [
    "com.google.android.gms.ads.DynamiteModules",
    "com.google.android.gms.ads.APPLICATION_ID",
    "com.google.android.gms.ads.AD_MANAGER_APP",
    "com.google.android.gms.ads.flag.OPTIMIZE_INITIALIZATION",
    "com.google.android.gms.ads.flag.OPTIMIZE_AD_LOADING",
    "com.google.android.gms.ads.flag.OPT_OUT_APP_START_INIT",
    "applovin.sdk.key",
    "android.adservices.AD_SERVICES_CONFIG",
]
AD_INIT_PROVIDERS = [
    "com.google.android.gms.ads.MobileAdsInitProvider",
    "com.applovin.sdk.AppLovinInitProvider",
]
# ad-only manifest entries that are not components (measured on all pins)
AD_USES_PERMISSIONS = (
    "com.google.android.gms.permission.AD_ID",
    "android.permission.ACCESS_ADSERVICES_AD_ID",
    "com.amazon.privacypass.ATTEST",
)
AD_USES_LIBRARIES = (
    "android.ext.adservices",
    "com.amazon.privacypass",
)
APP_REL = "smali/com/bambuna/podcastaddict/PodcastAddictApplication.smali"


def _journal_manifest(ctx: Context, mpath: Path) -> None:
    """Snapshot the manifest BEFORE surgery so revert can restore it.

    Called at the start of _strip_manifest, before any element is removed.
    """
    import json
    from xml.etree.ElementTree import tostring  # nosec B405 -- own journal snapshot

    jdir = ctx.journal_dir / "ads"
    jdir.mkdir(parents=True, exist_ok=True)
    snap = jdir / "manifest.json"
    if snap.is_file():
        return  # already captured
    snap.write_text(
        json.dumps({"xml": tostring(Manifest.load(mpath).root, encoding="unicode")}, indent=1)
    )


def record_class_shape(path: Path, root: Path, out: dict[str, dict]) -> None:
    """Record .class/.super/.implements for a file about to be deleted.

    The shim generator needs the REAL superclass: a shim that extends Object
    for a class that really extends View makes the ART verifier reject every
    method that passes it where a View is expected
    (VerifyError: 'this' MaxAdView not instance of android.view.View).
    """
    try:
        rel = path.relative_to(root).with_suffix("").as_posix()
        desc = "L" + rel + ";"
        sup, impls = "Ljava/lang/Object;", []
        for line in path.read_text(errors="ignore").splitlines():
            t = line.strip()
            if t.startswith(".super "):
                sup = t.split(None, 1)[1].strip()
            elif t.startswith(".implements "):
                impls.append(t.split(None, 1)[1].strip())
        out[desc] = {"super": sup, "implements": impls}
    except Exception:  # nosec B110 -- unreadable-file guard
        pass


def _save_class_shapes(ctx: Context, shapes: dict[str, dict]) -> None:
    import json

    ctx.anchors_dir.mkdir(parents=True, exist_ok=True)
    (ctx.anchors_dir / "deleted_sdk_classes.json").write_text(json.dumps(shapes, indent=1))


class AdsPatch(Patch):
    name = "ads"
    tier = "behaviour"
    ordered_after = ("premium", "security_behavior")

    # ------------------------------------------------------------- behaviour
    def _resolve_ad_targets(
        self, ctx: Context, *, tolerant: bool = False
    ) -> list[tuple[str, Path, SmaliMethodSpan]]:
        """Resolve each ad-stub target by evidence. Returns (label, path, span).

        A target that does not resolve is reported, never silently skipped:
        on 2026.12 the names moved (m0->n0, C->D, v/w->w/x, A0->B0, r->s), so a
        name-only lookup would edit the wrong method or nothing at all.

        `tolerant` is used by verify(): once the helpers are stubbed their
        bodies are identical no-ops, so strict resolution calls them ambiguous.
        That is a PATCHED state, not a failure -- verify enumerates every
        candidate and confirms each is stubbed.
        """
        out = []
        for key in A.METHOD_SPECS:
            if tolerant:
                hits = A.resolve_method_all_files(ctx.app_src, key, A.APP_CLASS_REL)
            else:
                hit = A.resolve_method_file(ctx.app_src, key, A.APP_CLASS_REL)
                hits = [(hit[0], hit[1])] if hit else []
            for span, path in hits:
                entry = (span.name, path, span)
                # Dedupe: after stubbing, a helper whose name is accepted by two
                # specs (banner_helper_1 takes (w,v), banner_helper_2 takes
                # (x,w,v)) would otherwise be reported -- and re-checked -- twice.
                if entry not in out:
                    out.append(entry)
        return out

    def _stub_helpers(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        path = ctx.app_src / APP_REL
        if not path.is_file():
            raise AnchorError(f"ads: {APP_REL} not found")
        try:
            targets = self._resolve_ad_targets(ctx)
        except AnchorError as exc:
            if "ambiguous" not in str(exc):
                raise
            # Re-run on an already-patched tree: our own stubs erased the
            # evidence that told the specs apart (banner_helper_1/2 share
            # names, and _is_stubbed matches every stubbed candidate).
            # Tolerate it ONLY when every candidate is already one of our
            # stubs -- otherwise the ambiguity is genuine and stays loud.
            from patcher.smali.editor import is_stub

            targets = self._resolve_ad_targets(ctx, tolerant=True)
            for _n, p, span in targets:
                ret = span.descriptor[span.descriptor.index(")") + 1 :]
                if not is_stub(p.read_bytes(), span, ret):
                    raise exc
            for _n, _p, span in targets:
                res.already += 1
                res.note(f"already stubbed: {span.name}{span.descriptor}")
            return res
        for _name, target_path, span in targets:
            reason = f"ad helper {span.name}{span.descriptor}"
            # each target is stubbed in the file that actually holds it: the
            # SDK initialiser lives outside the app class on 2026.12.1+
            e = stub_method(SmaliFile(target_path), span.name, span.descriptor, reason=reason)
            if e is None:
                res.already += 1
                continue
            if ctx.offline:
                res.note(f"[dry-run] would stub {span.name}{span.descriptor}")
                continue
            apply_edits([e], ctx.journal_dir, "ads", ctx.app_src)
            res.applied += 1
            res.note(f"stubbed {span.name}{span.descriptor} in {target_path.name}")
        return res

    def _strip_manifest(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        mpath = ctx.app_src / "AndroidManifest.xml"
        # Snapshot the pristine file BEFORE any in-memory removal.
        _journal_manifest(ctx, mpath)
        m = Manifest.load(mpath)
        for comp in m.names_matching(AD_MANIFEST_PREFIXES):
            if m.remove(comp):
                res.applied += 1
        for key in AD_META_KEYS:
            if m.remove_meta_data(key):
                res.applied += 1
        for prov in AD_INIT_PROVIDERS:
            for c in m.providers():
                if c.name == prov and m.remove(c):
                    res.applied += 1
        res.applied += m.remove_elements("uses-permission", AD_USES_PERMISSIONS)
        res.applied += m.remove_elements("uses-library", AD_USES_LIBRARIES)
        if not ctx.offline and res.applied:
            m.save()
        res.note(f"{res.applied} manifest entries removed")
        return res

    def _delete_trees(self, ctx: Context) -> PatchResult:
        """Delete SDK trees under every dex root, preserving com/applovin/shadow/**."""
        res = PatchResult()
        roots = [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]
        deleted_shapes: dict[str, dict] = {}
        for ns in config.DELETED_SDK_TREES:
            total = 0
            for root in roots:
                tree = root / ns
                if not tree.is_dir():
                    continue
                keep = tree / "shadow" if ns == "com/applovin" else None
                doomed = [
                    f
                    for f in sorted(tree.rglob("*.smali"))
                    if not (keep and (keep in f.parents or f == keep))
                ]
                if ctx.offline:
                    total += len(doomed)  # count only; a dry-run must not delete
                    continue
                for f in doomed:  # <- the live HTTP stack is kept
                    record_class_shape(f, root, deleted_shapes)
                    f.unlink()
                    total += 1
                if True:
                    for d in sorted(
                        (p for p in tree.rglob("*") if p.is_dir()),
                        key=lambda p: len(p.parts),
                        reverse=True,
                    ):
                        if keep and (keep in d.parents or d == keep):
                            continue
                        with contextlib.suppress(OSError):
                            d.rmdir()
            if not ctx.offline:
                _save_class_shapes(ctx, deleted_shapes)
            if total:
                label = f"{ns}: {total} files removed"
                if ns == "com/applovin":
                    label += " (shadow preserved)"
                res.note(label)
                res.applied += total
        return res

    def _delete_native(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        for so in sorted((ctx.app_src / "lib").rglob("*applovin-native-crash-reporter.so")):
            if ctx.offline:
                res.note(f"[dry-run] would remove {so.relative_to(ctx.app_src)}")
                continue
            so.unlink()
            res.applied += 1
            res.note(f"removed {so.relative_to(ctx.app_src)}")
        return res

    def resolve(self, ctx: Context) -> list[Anchor]:
        anchors = []
        p = ctx.app_src / APP_REL
        if not p.is_file():
            raise AnchorError(f"ads: {APP_REL} not found")
        for _name, path, span in self._resolve_ad_targets(ctx):
            rel = str(path.relative_to(ctx.app_src))
            anchors.append(
                Anchor(
                    id=f"{rel}:{span.name}",
                    file=rel,
                    descriptor=span.descriptor,
                    method=span.name,
                    evidence={"found_in_this_build": True},
                )
            )
        # absent-in-this-build targets are WARN-level anchors, not fatal.
        present = {span.name for _n, _p, span in self._resolve_ad_targets(ctx, tolerant=True)}
        for key, ev in A.specs_for(ctx.app_src)[0].items():
            if not (set(ev.names) & present):
                anchors.append(
                    Anchor(
                        id=f"{APP_REL}:{key}",
                        file=APP_REL,
                        descriptor="(absent)",
                        method=key,
                        confidence="missing",
                        evidence={"label": ev.label, "known_names": list(ev.names)},
                    )
                )
        return anchors

    def apply(self, ctx: Context) -> PatchResult:
        total = PatchResult()
        steps = (
            self._stub_helpers,
            self._strip_manifest,
            self._delete_trees,
            self._delete_native,
        )
        for step in steps:
            r = step(ctx)
            total.applied += r.applied
            total.already += r.already
            total.messages.extend(r.messages)
        return total

    def verify(self, ctx: Context) -> list[str]:
        out: list[str] = []
        # recorded shims legitimately live under deleted SDK paths.
        shim_files = set()
        sm = ctx.anchors_dir / ShimPatch.SHIM_MANIFEST
        if sm.is_file():
            shim_files = {line for line in sm.read_text().splitlines() if line}
        # 1. helpers stubbed (each in its own file: the SDK initialiser lives
        # outside the app class on 2026.12.1+)
        from patcher.smali.editor import is_stub

        resolved = self._resolve_ad_targets(ctx, tolerant=True)
        sf_cache: dict[Path, SmaliFile] = {}
        for _name, path, span in resolved:
            ret = span.descriptor[span.descriptor.index(")") + 1 :]
            if path not in sf_cache:
                sf_cache[path] = SmaliFile(path)
            if is_stub(sf_cache[path].data, span, ret):
                out.append(f"OK   {span.name}{span.descriptor} stubbed")
            else:
                out.append(f"FAIL {span.name}{span.descriptor} not stubbed")
        # absent targets are reported, not counted as patched.
        found_names = {s.name for _n, _p, s in resolved}
        for _key, ev in A.specs_for(ctx.app_src)[0].items():
            if not (set(ev.names) & found_names):
                out.append(f"WARN ad target absent in this build: {ev.label}")
        # 2. no surviving implementation classes from removed packages except shims/shadow
        survivors = []
        for root in [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]:
            for ns in config.DELETED_SDK_TREES:
                t = root / ns
                if not t.is_dir():
                    continue
                real = [
                    f
                    for f in t.rglob("*.smali")
                    if str(f.relative_to(ctx.app_src)) not in shim_files
                    and "/com/applovin/shadow/" not in f.as_posix()
                ]
                if real:
                    survivors.append(f"{ns}/{root.name}: {len(real)} files remain")
        if survivors:
            out.append("FAIL deleted trees still present: " + "; ".join(survivors))
        else:
            out.append("OK   all deleted SDK trees are empty")
        shadow = 0
        for root in [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]:
            shadow += sum(1 for _ in (root / "com/applovin/shadow").rglob("*.smali"))
        status = "OK " if shadow == config.SHADOW_PRESERVED else "FAIL"
        out.append(
            f"{status} com/applovin/shadow preserved "
            f"({shadow} files, expected {config.SHADOW_PRESERVED})"
        )
        # 3. ad init providers gone
        m = Manifest.load(ctx.app_src / "AndroidManifest.xml")
        names = {c.name for c in m.components()}
        for prov in AD_INIT_PROVIDERS:
            out.append(f"{'OK ' if prov not in names else 'FAIL'} {prov} absent from manifest")
        # 4. no first-party ad-SDK refs remain outside shadow
        from patcher.smali.reader import iter_smali_files

        bad = []
        for f in iter_smali_files([p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]):
            posix = f.as_posix()
            if "/com/applovin/shadow/" in posix:
                continue
            data = f.read_bytes()
            # shadow is the live HTTP stack; its own refs are legitimate
            if re.search(rb"Lcom/(applovin|fyber|inmobi|pubmatic)/(?!shadow/)", data):
                bad.append(str(f.relative_to(ctx.app_src)))
        if bad:
            out.append(
                f"WARN {len(bad)} non-shadow files still reference ad SDKs: " + ", ".join(bad[:5])
            )
        return out
