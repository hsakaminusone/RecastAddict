"""MODULE telemetry -- first-party analytics + ad-serving suppression.

Literal rewrite: each blocked endpoint (all measured full absolute URLs, each
used once in URL construction) is replaced with an unroutable address.
"""

from __future__ import annotations

import re

from patcher import config
from patcher.patches.base import Anchor, AnchorError, Context, Patch, PatchResult
from patcher.shimfile import our_shim
from patcher.smali.editor import Edit, apply_edits

UNROUTABLE = "http://127.0.0.1:1/blocked-by-policy"

FIREBASE_DELETE = ("com/google/firebase/analytics", "com/google/firebase/crashlytics")
FIREBASE_KEEP = (
    "com/google/firebase/messaging",
    "com/google/firebase/components",
    "com/google/firebase/common",
    "com/google/firebase/iid",
)


def _endpoint(ep: str) -> str:
    return ep if ep.endswith(".php") else ep + ".php"


class TelemetryPatch(Patch):
    name = "telemetry"
    tier = "behaviour"
    ordered_after = ("ads",)

    def resolve(self, ctx: Context) -> list[Anchor]:
        anchors, found = [], 0
        for f in sorted(ctx.app_src.rglob("*.smali")):
            data = f.read_bytes()
            for ep in config.BLOCKED_ENDPOINTS:
                full = _endpoint(ep).encode()
                if full in data:
                    found += 1
                    anchors.append(
                        Anchor(
                            id=f"{f.relative_to(ctx.app_src)}:{ep}",
                            file=str(f.relative_to(ctx.app_src)),
                            descriptor=full.decode(),
                            evidence={"single_use": data.count(full) == 1},
                        )
                    )
        if not found:
            raise AnchorError("telemetry: no blocked endpoint literals found (already patched?)")
        return anchors

    def apply(self, ctx: Context) -> PatchResult:
        res = PatchResult()
        for f in sorted(ctx.app_src.rglob("*.smali")):
            data = f.read_bytes()
            new = data
            for ep in config.BLOCKED_ENDPOINTS:
                full = _endpoint(ep).encode()
                if full not in new:
                    continue
                host = b"https://addictpodcast.com/ws/php/v4.1/"
                pat = re.compile(
                    rb'(const-string [vp]\d+, ")' + re.escape(host + full) + rb'[^"]*"'
                )
                new = pat.sub(rb"\g<1>" + UNROUTABLE.encode() + rb'"', new)
            if new != data:
                if ctx.offline:
                    res.note(f"[dry-run] would rewrite endpoints in {f.relative_to(ctx.app_src)}")
                    continue
                apply_edits(
                    [
                        Edit(
                            path=f,
                            old_bytes=data,
                            new_bytes=new,
                            reason="telemetry endpoint -> unroutable",
                        )
                    ],
                    ctx.journal_dir,
                    "telemetry",
                )
                res.applied += 1
                res.note(f"rewrote endpoints in {f.relative_to(ctx.app_src)}")
        if not ctx.offline:
            self._delete_firebase(ctx, res)
        return res

    def _roots(self, ctx: Context) -> list:
        return [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]

    def _delete_firebase(self, ctx: Context, res: PatchResult) -> None:
        """Delete analytics/crashlytics under every dex root, plus their
        registrar discovery entries (FirebaseInitProvider would otherwise load
        the shims and NPE iterating a null component list)."""
        for sub in FIREBASE_DELETE:
            n = 0
            for root in self._roots(ctx):
                t = root / sub
                if not t.is_dir():
                    continue
                doomed = sorted(t.rglob("*.smali"))
                if ctx.offline:
                    n += len(doomed)
                    continue
                for f in doomed:
                    f.unlink()
                    n += 1
            if n:
                res.applied += n
                res.note(f"removed {sub} ({n} files)")
        if not ctx.offline:
            self._strip_registrar_discovery(ctx, res)

    def _strip_registrar_discovery(self, ctx: Context, res: PatchResult) -> None:
        """Remove ComponentDiscoveryService entries for deleted registrars."""
        from patcher.manifest import Manifest

        doomed_ns = tuple(s.replace("/", ".") for s in FIREBASE_DELETE)
        mpath = ctx.app_src / "AndroidManifest.xml"
        m = Manifest.load(mpath)
        cut = 0
        for name, _el in m.meta_datas():
            if not name.startswith("com.google.firebase.components:"):
                continue
            registrar = name.split(":", 1)[1]
            if registrar.startswith(doomed_ns) and m.remove_meta_data(name):
                cut += 1
        if cut:
            m.save()
            res.applied += cut
            res.note(f"removed {cut} registrar discovery entries ({', '.join(doomed_ns)})")

    def verify(self, ctx: Context) -> list[str]:
        out: list[str] = []
        remaining = 0
        for f in sorted(ctx.app_src.rglob("*.smali")):
            data = f.read_bytes()
            for ep in config.BLOCKED_ENDPOINTS:
                if b"https://addictpodcast.com/ws/php/v4.1/" + _endpoint(ep).encode() in data:
                    remaining += 1
        if remaining:
            out.append(
                f"FAIL {remaining} telemetry endpoint literals still resolve to addictpodcast.com"
            )
        else:
            out.append(
                f"OK  all {len(config.BLOCKED_ENDPOINTS)} telemetry endpoints "
                "redirected to an unroutable address"
            )
        roots = [p for p in sorted(ctx.app_src.glob("smali*")) if p.is_dir()]
        for sub in FIREBASE_KEEP:
            n = sum(1 for r in roots if (r / sub).is_dir() for _ in (r / sub).rglob("*.smali"))
            out.append(f"{'OK ' if n else 'WARN'} firebase keep-list {sub} present ({n} files)")
        for sub in FIREBASE_DELETE:
            # Count real code only; our shims mean the SDK is gone.
            files = [f for r in roots if (r / sub).is_dir() for f in (r / sub).rglob("*.smali")]
            real = [f for f in files if not our_shim(f)]
            if real:
                out.append(f"FAIL {sub}: {len(real)} real files remain")
            elif files:
                out.append(
                    f"OK  {sub} removed ({len(files)} shim(s) only -- "
                    f"survivor references kept resolvable)"
                )
            else:
                out.append(f"OK  {sub} removed")
        from patcher.manifest import Manifest

        doomed_ns = tuple(s.replace("/", ".") for s in FIREBASE_DELETE)
        leftovers = [
            name
            for name, _el in Manifest.load(ctx.app_src / "AndroidManifest.xml").meta_datas()
            if name.startswith("com.google.firebase.components:")
            and name.split(":", 1)[1].startswith(doomed_ns)
        ]
        if leftovers:
            out.append(
                f"FAIL {len(leftovers)} registrar discovery entries survive for removed SDKs: "
                f"{leftovers[0]}"
            )
        else:
            out.append("OK  no registrar discovery entries for removed SDKs")
        return out
