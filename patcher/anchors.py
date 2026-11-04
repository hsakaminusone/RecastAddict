"""Anchor registry: version-independent evidence once, obfuscated names per
version profile. R8 renames every release, so resolution matches on literals
and method shapes that survive obfuscation; a release with no profile falls
back to all known names and fails loud on a real rename.

Adding a release is one dict entry: `"2026.14": {"applovin_init": ("p3",)}`.
Class anchors use CLASS_PROFILES the same way: the patch names a role
("ad_gates"), the profile maps it to this release's obfuscated method name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import-cycle safe: never executed at runtime
    from patcher.smali.span import SmaliMethodSpan


# --------------------------------------------------------------------- result


@dataclass
class Resolution:
    """A resolved anchor, carrying the evidence that identified it."""

    path: Path
    rel: str
    spec: str
    rule: str
    evidence: dict = field(default_factory=dict)


# ----------------------------------------------------------------- base specs

# Evidence literals must survive our own patches: never anchor on strings
# inside a method another patch stubs.


@dataclass(frozen=True)
class MethodEvidence:
    """Version-independent evidence for one behavioural anchor."""

    label: str
    strings: tuple[str, ...] = ()
    invokes: tuple[str, ...] = ()
    forbid_strings: tuple[str, ...] = ()
    # names the spec has been observed to use, oldest first. The registry adds
    # any profile aliases on top of these.
    names: tuple[str, ...] = ()
    # "app" resolves in APP_CLASS_REL only; "tree" falls back to a full scan
    # (R8 can move the body into a synthetic lambda).
    scope: str = "app"
    note: str = ""

    def with_names(self, names: tuple[str, ...]) -> MethodEvidence:
        return replace(self, names=tuple(names))


@dataclass(frozen=True)
class ClassEvidence:
    """Version-independent evidence for one obfuscated class."""

    label: str
    strings: tuple[str, ...] = ()
    methods: tuple[tuple[str, str], ...] = ()
    forbid_strings: tuple[str, ...] = ()
    note: str = ""

    def with_names(self, names: tuple[str, ...]) -> ClassEvidence:
        return self  # classes are resolved by shape, not by name


METHOD_SPECS: dict[str, MethodEvidence] = {
    # The 7 behavioural ad stubs in PodcastAddictApplication (plus the SDK
    # initialiser, which R8 may extract into a synthetic lambda).
    "applovin_init": MethodEvidence(
        label="AppLovin SDK initializer",
        strings=(
            # The SDK key is a stable, version-independent literal.
            "w8i12H9nSUHNhZb4NGvt-5KFuiDPRvHyUSh6O_6Tc9v2Tp4fxCeeAbAQZD_iIn8Vt1TSd7zEtc437oHcd_z5Ls",
        ),
        invokes=(
            "builder(Ljava/lang/String;)",
            "setMediationProvider(Ljava/lang/String;)",
        ),
        names=("n0", "m0"),
        scope="tree",
        note="SDK key + builder + setMediationProvider('max'); lambda-extracted on 2026.12.1+",
    ),
    "ad_unit_selector": MethodEvidence(
        label="ad-unit-ID + format selector",
        strings=(
            "a124058d-8cc9-47b5-b58f-dc8ffbbb7652",  # leader ad unit id
            "de3fe86d-fd1d-4e63-bc52-e9175d7ea5f1",  # banner ad unit id
            "Lcom/applovin/mediation/MaxAdFormat;",
        ),
        invokes=("isTablet(Landroid/content/Context;)",),
        names=("D", "C"),
        note="selects banner/leader ad unit id by device type",
    ),
    "banner_post": MethodEvidence(
        label="ad-load Runnable post",
        # Field name (M0->P0), Runnable class and poster method (i->k) all
        # drift; only the shape is stable. Matched by the field's type suffix.
        strings=(":Lcom/applovin/mediation/ads/MaxAdView;", "Ljava/lang/Runnable;"),
        invokes=("new-instance",),
        names=("s", "r"),
        note="posts the runnable that loads the ad view",
    ),
    "banner_helper_1": MethodEvidence(
        label="banner helper #1 (2-arg wrapper)",
        # Measures the view, then DELEGATES to the 4-arg builder -- so it is
        # told apart from its callee by containing getWidth/getSimpleName but
        # NOT getAdaptiveSize.
        strings=("getWidth", "getSimpleName"),
        forbid_strings=("getAdaptiveSize",),
        names=("w", "v"),
        note="2-arg banner wrapper that delegates to the 4-arg builder",
    ),
    "banner_helper_2": MethodEvidence(
        label="banner helper #2 (4-arg builder)",
        strings=("getAdaptiveSize", "Lcom/applovin/mediation/MaxAdFormat;"),
        invokes=("getAdaptiveSize(I",),
        names=("x", "w", "v"),
        note="4-arg banner builder using MaxAdFormat.getAdaptiveSize",
    ),
    "ad_teardown": MethodEvidence(
        label="ad-view teardown",
        # Field name moved M0 -> P0 on 2026.12.1; matched by type suffix.
        strings=(
            "stopAutoRefresh",
            "destroy",
            ":Lcom/applovin/mediation/ads/MaxAdView;",
        ),
        invokes=(
            "stopAutoRefresh()",
            "destroy()",
        ),
        names=("B0", "A0"),
        note="declared-synchronized; tears the MaxAdView down",
    ),
    "screen_status": MethodEvidence(
        label="ad screen-status tracking",
        strings=("setScreenStatus(", ":Lcom/applovin/mediation/ads/MaxAdView;"),
        forbid_strings=("stopAutoRefresh", "getAdaptiveSize", "isTablet"),
        names=("V0", "U0"),
        note="tracks ad screen visibility via the MaxAdView field",
    ),
}


CLASS_SPECS: dict[str, ClassEvidence] = {
    "premium_gate": ClassEvidence(
        label="premium / IAP gate",
        # Subscription state read from these SharedPreferences names.
        strings=("pref_previousTimerUpdate", "pref_nextTimerUpdate"),
        # 11/12 also have g(Context)/m(Z); 13 renamed g->h and l. These four
        # shapes are identical on all four pins.
        methods=(
            ("f", "()Z"),
            ("d", "(Landroid/content/Context;)Z"),
            ("e", "(Landroid/content/Context;Z)Z"),
            ("k", "(Landroid/content/Context;)Z"),
        ),
        forbid_strings=("recast-shim",),
        note="subscription active / donate-app present / ad gates / upsell",
    ),
    "installer_gate": ClassEvidence(
        label="installer / signature gate",
        # The package-name literals (cm.aptoide.pt, com.apkpure.aegon, ...) were
        # replaced by hashed int[] sets on 2026.12.1+; "AppSecurityHelper" sits
        # in <clinit> and "isAppSignatureLegit" in d()Z, which no patch stubs.
        strings=("AppSecurityHelper", "isAppSignatureLegit"),
        methods=(
            ("c", "()Z"),
            ("d", "()Z"),
            ("e", "()Z"),
            ("f", "()Z"),
            ("g", "(Landroid/content/Context;Landroid/content/pm/PackageInfo;Z)Z"),
        ),
        forbid_strings=("recast-shim",),
        note="signature allowlist + installer allowlist + donate-app installer",
    ),
}


# --------------------------------------------------------------------- profiles

# One entry per observed target-version, containing ONLY what changed: the
# method names. Adding a future release is a data addition here. Nothing else.
#
# To support a new release you add:
#     "2026.14": {"applovin_init": ("p3",), "banner_post": ("u",), ...}
#
# If a release is absent, resolution falls back to the union of every name any
# profile declares (plus BASE), so an unchanged build still resolves, and a
# renamed one fails loud instead of patching the wrong method.

PROFILES: dict[str, dict[str, tuple[str, ...]]] = {
    "2026.11": {},
    "2026.12": {
        "applovin_init": ("n0",),
        "ad_unit_selector": ("D",),
        "banner_post": ("s",),
        "banner_helper_1": ("w",),
        "banner_helper_2": ("x",),
        "ad_teardown": ("B0",),
        "screen_status": ("V0",),
    },
    "2026.12.1": {
        "applovin_init": ("accept",),
        "ad_unit_selector": ("D",),
        "banner_post": ("s",),
        "banner_helper_1": ("w",),
        "banner_helper_2": ("x",),
        "ad_teardown": ("C0",),
        "screen_status": ("W0",),
    },
    "2026.13": {
        "applovin_init": ("accept",),
        "ad_unit_selector": ("E",),
        "banner_post": ("s",),
        "banner_helper_1": ("w",),
        "banner_helper_2": ("x",),
        "ad_teardown": ("E0",),
        "screen_status": ("Y0",),
    },
    "2026.14": {
        "applovin_init": ("accept",),
        "ad_unit_selector": ("E",),
        "banner_post": ("s",),
        "banner_helper_1": ("w",),
        "banner_helper_2": ("x",),
        "ad_teardown": ("F0",),
        "screen_status": ("Z0",),
    },
}


# -------------------------------------------------- class-anchor role names
#
# The patches address methods inside CLASS_SPECS classes by ROLE, not name:
# the name is release data, the role is the patch's contract. 2026.13 moved
# premium ad_gates g->h and upsell k->l (k became donate-install confirm),
# and 13/14 split a pure-state g()Z out of f() (premium_state).

BASE_CLASS_ROLES: dict[str, str] = {
    "premium_gate:subscription": "f",
    "premium_gate:donate_app": "d",
    "premium_gate:ad_gates": "g",
    "premium_gate:upsell": "k",
    "installer_gate:iap_can_use": "f",
    "installer_gate:cert_allowlist": "g",
    "installer_gate:installer_allowlist": "c",
    "installer_gate:donate_installer": "e",
}

# premium_state exists only where the class split it out of f(); a role that
# is in neither BASE nor a profile is absent in that build.
CLASS_PROFILES: dict[str, dict[str, str]] = {
    "2026.13": {
        "premium_gate:ad_gates": "h",
        "premium_gate:upsell": "l",
        "premium_gate:premium_state": "g",
    },
    "2026.14": {
        "premium_gate:ad_gates": "h",
        "premium_gate:upsell": "l",
        "premium_gate:premium_state": "g",
    },
}


def class_role_name(app_src: Path, key: str, role: str) -> str | None:
    """Method name for `key:role` on this release; None when absent here."""
    version = detect_version(app_src)
    overlay = CLASS_PROFILES.get(version, {}) if version else {}
    if version:
        return overlay.get(f"{key}:{role}", BASE_CLASS_ROLES.get(f"{key}:{role}"))
    # unknown version: prefer the base name so an unmapped rename still fails
    # at method lookup with the full class inventory, not at name resolution
    return BASE_CLASS_ROLES.get(f"{key}:{role}")


def _all_known_names() -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for key, spec in METHOD_SPECS.items():
        out[key] = list(spec.names)
    for _ver, overlay in PROFILES.items():
        for key, names in overlay.items():
            out.setdefault(key, [])
            for n in names:
                if n not in out[key]:
                    out[key].append(n)
    return {k: tuple(v) for k, v in out.items()}


_FALLBACK_NAMES = _all_known_names()


# ----------------------------------------------------------- version detection


def detect_version(app_src: Path) -> str | None:
    """The target's versionName, from the decoded apktool.yml.

    Used only to pick a PROFILE. Unknown or absent is fine: we fall back to the
    union of all known names, which resolves correctly until a real rename.
    """
    try:
        text = (Path(app_src) / "apktool.yml").read_text()
    except OSError:
        return None
    m = re.search(r"^\s*versionName:\s*['\"]?([0-9][^'\"\s]*)", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def specs_for(
    app_src: Path,
) -> tuple[dict[str, MethodEvidence], str | None]:
    """(effective method specs, version used). Applies the matching profile."""
    app_src = Path(app_src)
    version = detect_version(app_src)
    overlay = PROFILES.get(version) if version else None
    out: dict[str, MethodEvidence] = {}
    for key, spec in METHOD_SPECS.items():
        if overlay and key in overlay:
            names = tuple(dict.fromkeys((*spec.names, *overlay[key])))
        else:
            # unknown version: accept every name we have ever seen
            names = tuple(dict.fromkeys((*spec.names, *_FALLBACK_NAMES.get(key, ()))))
        out[key] = spec.with_names(names)
    return out, version


# ------------------------------------------------------------------- resolvers
#
# These deliberately do NOT import patcher.patches.* at module scope: that
# package imports the patch modules, which import this one. AnchorError is
# therefore imported lazily inside each raiser.


def _dex_roots(app_src: Path) -> list[Path]:
    app_src = Path(app_src)
    return [p for p in sorted(app_src.glob("smali*")) if p.is_dir()]


def _anchor_error(msg: str) -> Exception:
    from patcher.patches.base import AnchorError

    return AnchorError(msg)


def _rel(app_src: Path, path: Path) -> str:
    try:
        return str(path.relative_to(app_src))
    except ValueError:
        return str(path)


def _body(span: SmaliMethodSpan, data: bytes) -> bytes:
    return span.body(data)


def _is_stubbed(span: SmaliMethodSpan, data: bytes) -> bool:
    """True when a method body is a constant-return stub written by us.

    A spec whose evidence lives inside the body of a method that OUR OWN patch
    stubs (the AppLovin initialiser's SDK key is the case in point) cannot
    re-resolve on an already-patched tree -- the evidence was deleted by the
    same patch that made it necessary. Recognising our own stub keeps the
    second run idempotent instead of failing with "no anchor matches".
    """
    body = span.body(data).strip()
    if not body:
        return True
    return body in (
        b".locals 0\n    return-void",
        b".locals 0\nreturn-void",
        b".locals 1\n    const/4 v0, 0x0\n    return-void",
        b".locals 1\n    const/4 v0, 0x1\n    return v0",
        # object-returning stubs (our ad-unit selector returns Lqr0;/Lm70;)
        b".locals 1\n    const/4 v0, 0x0\n    return-object v0",
        b".locals 1\n    const/4 v0, 0x0\n    return v0",
    )


def match_method(
    spec: MethodEvidence, span: SmaliMethodSpan, data: bytes, *, allow_stub: bool = True
) -> bool:
    """True when `span` satisfies the version-independent evidence.

    `invokes` entries are either a bare instruction (`new-instance`) or a call
    target (`builder(Ljava/lang/String;)`). The form is detected, not assumed:
    a bare opcode has no argument list, so prefixing "->" to it creates a
    token that never appears and the spec silently never matches.

    allow_stub=False (tree scans) skips our stub short-circuit: the whole tree
    is full of coincidental stub-shaped methods (11 named accept/n0/m0 on
    2026.12.1), so only real evidence is unambiguous there.
    """
    if span.name not in spec.names:
        return False
    body = _body(span, data)
    # Idempotency: a spec whose evidence lived inside a body that OUR OWN patch
    # stubbed cannot re-resolve on an already-patched tree. Accept our stub.
    if allow_stub and _is_stubbed(span, data):
        return True
    if any(x.encode() not in body for x in spec.strings):
        return False
    if any(x.encode() in body for x in spec.forbid_strings):
        return False
    return all(_invoke_needle(token).encode() in body for token in spec.invokes)


def _invoke_needle(token: str) -> str:
    """'builder(Ljava/lang/String;)' -> '->builder(Ljava/lang/String;)';
    'new-instance' stays 'new-instance' (a bare opcode has no arrow)."""
    return "->" + token if "(" in token else token


def _find_method_spans(data: bytes, path: Path) -> list[SmaliMethodSpan]:
    """Lazy import: patcher.smali.span must not create an import cycle."""
    from patcher.smali.span import find_method_spans

    return list(find_method_spans(data, path))


def match_class(spec: ClassEvidence, data: bytes) -> bool:
    if any(x.encode() not in data for x in spec.strings):
        return False
    if any(x.encode() in data for x in spec.forbid_strings):
        return False
    if not spec.methods:
        return True
    have = {(s.name, s.descriptor) for s in _find_method_spans(data, _NO_PATH)}
    return all(m in have for m in spec.methods)


def resolve_class(app_src: Path, key: str = "installer_gate") -> Resolution:
    """Resolve a class spec to exactly one file. Never guesses.

    Zero or several matches both raise: picking one arbitrarily is the bug this
    whole module exists to prevent.
    """
    app_src = Path(app_src)
    spec = CLASS_SPECS[key]
    found = []
    for root in _dex_roots(app_src):
        for f in sorted(root.rglob("*.smali")):
            try:
                data = f.read_bytes()
            except OSError:
                continue
            if match_class(spec, data):
                found.append((f, root))
    if not found:
        raise _anchor_error(
            f"{key}: no class matches evidence for {spec.label!r}. "
            f"strings={list(spec.strings)} methods={list(spec.methods)}"
        )
    if len(found) > 1:
        raise _anchor_error(
            f"{key}: evidence for {spec.label!r} is ambiguous -- "
            f"{len(found)} classes match: {[str(f) for f, _r in found[:6]]}. "
            f"Tighten the spec."
        )
    f, _root = found[0]
    _specs, version = specs_for(app_src)
    return Resolution(
        path=f,
        rel=_rel(app_src, f),
        spec=key,
        rule=f"{key} class evidence (version={version})",
        evidence={"label": spec.label, "version": version, "strings": list(spec.strings)},
    )


_LAMBDA_CAPTURE = (
    b".field public final synthetic a:B",
    b".field public final synthetic b:Ljava/lang/Object;",
    b".method public synthetic constructor <init>(Ljava/lang/Object;B)V",
)


def _is_capture_lambda(data: bytes) -> bool:
    """A concrete synthetic lambda that captures an object + a byte dispatch.

    R8 emits this shape for the SDK initialiser on 2026.12.1+ (b4/i4).
    Stub-shaped coincidental matches are all `interface abstract` or
    `abstract` classes, never this shape -- and unlike an app-class reference,
    these markers sit outside the stubbed method body, so they survive apply.
    """
    return all(m in data for m in _LAMBDA_CAPTURE)


def _match_tree(spec: MethodEvidence, span: SmaliMethodSpan, data: bytes) -> bool:
    """Tree-scope matcher: strict evidence, or OUR stub of the same method.

    Strict evidence is required in tree scans (11 coincidental stub-shaped
    accept/n0/m0 methods exist per build). For idempotent re-resolution after
    apply, a stub-shaped match is accepted only when its file is the capture
    lambda that held the SDK initialiser.
    """
    if match_method(spec, span, data, allow_stub=False):
        return True
    return span.name in spec.names and _is_stubbed(span, data) and _is_capture_lambda(data)


def _scan_tree(app_src: Path, spec: MethodEvidence) -> list[tuple[SmaliMethodSpan, Path, bytes]]:
    """(span, file, data) for every match anywhere in the tree (scope="tree")."""
    out: list[tuple[SmaliMethodSpan, Path, bytes]] = []
    for root in _dex_roots(app_src):
        for f in sorted(root.rglob("*.smali")):
            try:
                data = f.read_bytes()
            except OSError:
                continue
            out.extend(
                (s, f, data) for s in _find_method_spans(data, f) if _match_tree(spec, s, data)
            )
    return out


def resolve_method_file(
    app_src: Path, key: str, app_rel: str
) -> tuple[SmaliMethodSpan, Path, bytes] | None:
    """Like resolve_method, but also reports the declaring file.

    A scope="tree" spec can live outside app_rel (the SDK initialiser moved
    into a synthetic lambda on 2026.12.1+), and the caller must edit the file
    that actually holds the method.
    """
    app_src = Path(app_src)
    specs, _version = specs_for(app_src)
    spec = specs[key]
    path = app_src / app_rel
    if not path.is_file():
        raise _anchor_error(f"{key}: {app_rel} not found")
    data = path.read_bytes()
    hits = [s for s in _find_method_spans(data, path) if match_method(spec, s, data)]
    if not hits and spec.scope == "tree":
        tree_hits = _scan_tree(app_src, spec)
        if len(tree_hits) > 1:
            raise _anchor_error(
                f"{key}: {spec.label!r} is ambiguous -- {len(tree_hits)} methods match "
                f"across the tree: {[s.name for s, _p, _d in tree_hits]}"
            )
        return tree_hits[0] if tree_hits else None
    if not hits:
        return None
    if len(hits) > 1:
        raise _anchor_error(
            f"{key}: {spec.label!r} is ambiguous -- {len(hits)} methods match "
            f"names={list(spec.names)}: {[s.name for s in hits]}"
        )
    return hits[0], path, data


def resolve_method(app_src: Path, key: str, app_rel: str) -> tuple[SmaliMethodSpan, bytes] | None:
    """Resolve a method spec to exactly one span. Returns (span, file_data).

    None only when the spec is genuinely absent in this build, which is a
    legitimate outcome (a feature was removed). Anything else raises.
    """
    hit = resolve_method_file(app_src, key, app_rel)
    if hit is None:
        return None
    span, _path, data = hit
    return span, data


# ------------------------------------------------------- APP_CLASS_REL + compat
#
# APP_CLASS_REL: first-party code is NOT obfuscated, so it is safe to name.
APP_CLASS_REL = "smali/com/bambuna/podcastaddict/PodcastAddictApplication.smali"


_NO_PATH = Path("")  # sentinel: no real file backs an in-memory parse


def resolve_method_all_files(
    app_src: Path, key: str, app_rel: str
) -> list[tuple[SmaliMethodSpan, Path]]:
    """(span, file) for every match, WITHOUT the ambiguity error. See
    resolve_method_all for why tolerant enumeration exists."""
    app_src = Path(app_src)
    specs, _version = specs_for(app_src)
    spec = specs[key]
    path = app_src / app_rel
    if not path.is_file():
        return []
    data = path.read_bytes()
    out = [(s, path) for s in _find_method_spans(data, path) if match_method(spec, s, data)]
    if not out and spec.scope == "tree":
        return [(s, p) for s, p, _d in _scan_tree(app_src, spec)]
    return out


def resolve_method_all(app_src: Path, key: str, app_rel: str) -> list[SmaliMethodSpan]:
    """Every span matching a spec, WITHOUT the ambiguity error.

    Needed by verify(): after `apply` has stubbed the ad helpers, their bodies
    are identical no-ops, so strict resolution cannot tell them apart -- but
    that is a *patched* state, not an error. verify() wants to enumerate all
    candidates and confirm each one is stubbed; apply() wants exactly one.
    """
    return [s for s, _p in resolve_method_all_files(app_src, key, app_rel)]


# The telemetry HTTP chokepoint: the method every first-party backend call
# funnels through. Class and return type are obfuscated (fo5/Ltb4 in 2026.11,
# sp5/Led4 in 2026.12), so resolution uses the stable shape: a method taking
# exactly (String, List, boolean), returning a reference type, invoked from a
# file holding backend endpoint literals.

CHOKEPOINT_ARGS = "Ljava/lang/String;Ljava/util/List;Z"

_INVOKE_RE = re.compile(
    rb"invoke-\w+ \{[^}]*\},\s*(L[A-Za-z0-9/$_]+;)->([A-Za-z0-9_$]+)"
    rb"\(" + CHOKEPOINT_ARGS.encode() + rb"\)(L[A-Za-z0-9/$_]+;)"
)


def resolve_chokepoint(app_src: Path) -> tuple[Path, SmaliMethodSpan, bytes] | None:
    """Locate the backend dispatcher by evidence, not by obfuscated name.

    Returns (declaring file, span, file bytes), or None when the tree does not
    exhibit the evidence. None lets the caller FAIL the audit, which is the
    correct outcome on an unrecognised build -- the opposite of the old silent
    "0 call sites, looks fine" pass.
    """
    from patcher import config

    app_src = Path(app_src)
    files: list[Path] = []
    for root in _dex_roots(app_src):
        files.extend(sorted(root.rglob("*.smali")))

    # 1. which classes actually hold the backend endpoint literals
    endpoint = b"ws/php/v4.1/"
    holding: set[Path] = set()
    bodies: dict[Path, bytes] = {}
    for f in files:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        bodies[f] = data
        if any(endpoint + ep.encode() in data for ep in config.BLOCKED_ENDPOINTS):
            holding.add(f)
    if not holding:
        return None

    # 2. which (String,List,boolean)->ref methods are INVOKED anywhere
    invoked_names: set[str] = set()
    for data in bodies.values():
        for m in _INVOKE_RE.finditer(data):
            invoked_names.add(m.group(2).decode())
    if not invoked_names:
        return None

    # 3. the declaration must be INVOKED FROM an endpoint-holding file. The
    #    dispatcher itself is usually declared elsewhere (2026.12: sp5.smali,
    #    called from kp5.smali which holds the literals), so "declared in a
    #    literal-holding file" is the wrong link -- "called from one" is right.
    callers: dict[str, set[Path]] = {}
    for f in holding:
        data = bodies[f]
        for m in _INVOKE_RE.finditer(data):
            callers.setdefault(m.group(2).decode(), set()).add(f)
    if not callers:
        return None

    want = "(" + CHOKEPOINT_ARGS + ")"
    out: list[tuple[Path, SmaliMethodSpan, bytes]] = []
    for f in files:
        if f not in bodies:
            continue
        data = bodies[f]
        for span in _find_method_spans(data, f):
            if span.name not in callers:
                continue
            if span.descriptor.split(")")[0] + ")" != want:
                continue
            if not span.descriptor.endswith(";"):
                continue
            out.append((f, span, data))
    return out[0] if len(out) == 1 else None
