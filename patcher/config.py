"""Pinned target constants and toolchain paths.

Everything here is a measured fact about the pinned APK. The patcher must
refuse to run against anything that does not match -- see policy.py.
"""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------- pinned target
#
# Both pins carry the same original signer certificate, so both are untampered
# release builds; the name drift between them is R8 re-obfuscation.

# A pin is accepted only when SHA-256, package, versionName, versionCode and
# signer all match. Adding a release is two data edits:
#   1. one entry here, and
#   2. one PROFILES entry in patcher/anchors.py naming the obfuscated names.

PINS: tuple[dict, ...] = (
    {
        "version_name": "2026.11",
        "version_code": "21774",
        "sha256": "d115d3361a29822877b2940f547b2b868cd26540521d68e32628cf0de3bffbce",
        "legacy": True,
        "smali_files": 19468,
    },
    {
        "version_name": "2026.12",
        "version_code": "21777",
        "sha256": "631148e1d06118d92d32960503661570b26b4e7ef5504cdf708f9eabfb9e7946",
        "legacy": False,
        "smali_files": 19473,
    },
)


# The pin is never configured and never defaulted: it is detected from the
# APK itself (badging version + SHA-256, matched against PINS). Anything that
# is not one of the supported builds fails loudly at selection time, and again
# at the policy gate.
def supported_versions() -> list[str]:
    """Version names this patcher supports. Currently exactly two."""
    return [p["version_name"] for p in PINS]


def pin_for(version_name: str) -> dict:
    """The pin record for `version_name`.

    Raises KeyError naming the supported versions -- an unsupported build
    fails loudly instead of patching the wrong target.
    """
    for p in PINS:
        if p["version_name"] == version_name:
            return p
    raise KeyError(f"unsupported version {version_name!r}; supported: {supported_versions()}.")


# Selection state, filled once by select_input(). A plain dict (not `global`
# rebinding) so the linter stays quiet and readers see every write site here.
_STATE: dict = {"apk": None, "pin": None}


def source_apk() -> Path:
    """The selected input APK path. Raises until select_input() has run."""
    if _STATE["apk"] is None:
        raise RuntimeError("no input APK selected (select_input() was not called)")
    return _STATE["apk"]


def identify_pin(apk: Path) -> dict:
    """Match an APK file against the supported pins by version + SHA-256.

    Anything else -- wrong version, repack, re-sign -- raises PolicyError
    naming the supported versions. The signer itself is re-checked by the
    policy gate.
    """
    from patcher import policy

    try:
        info = policy.inspect(Path(apk))
    except Exception as exc:
        raise policy.PolicyError(f"cannot identify {apk}: {exc}") from exc
    for p in PINS:
        if (
            info.version_name == p["version_name"]
            and info.version_code == p["version_code"]
            and info.sha256.lower() == p["sha256"].lower()
        ):
            return p
    raise policy.PolicyError(
        f"{apk} is not a supported build "
        f"(got {info.version_name}/{info.version_code} {info.sha256[:16]}...); "
        f"supported versions: {supported_versions()}."
    )


def select_input(explicit: str) -> tuple[Path, dict]:
    """Identify this run's input APK and record the selection.

    Call once, before any command that touches the input.
    """
    p = Path(explicit)
    if not p.is_file():
        raise FileNotFoundError(f"no such APK: {p}")
    pin = identify_pin(p)
    _STATE["apk"] = p
    _STATE["pin"] = pin
    return p, pin


# Original signer: rejects same-package/version APKs signed by another key.
SIGNER_SHA256 = "1CF0C0697B5D56A9B45C302DD038FF1D3EF53AEFCF17C36E41F816AFE66ACC9C"
SIGNER_SHA1 = "751A69848DC3BC374EE20BF705CAB6FB641E6AC1"

PACKAGE = "com.bambuna.podcastaddict"

MIN_SDK = 26
TARGET_SDK = 36

# ------------------------------------------------------------------------ paths
# All working paths derive from this file's location: the repo root holds
# app_src/, and patcher/ holds anchors/, out/ and .journal/. No env vars,
# no machine-specific defaults.
ROOT = Path(__file__).resolve().parent.parent
APP_SRC = ROOT / "app_src"
PATCHER_DIR = ROOT / "patcher"
ANCHORS_DIR = PATCHER_DIR / "anchors"
OUT_DIR = PATCHER_DIR / "out"
JOURNAL_DIR = PATCHER_DIR / ".journal"

# ------------------------------------------------------------------- toolchain
# Every tool resolves via PATH (verified by cli.check_deps). No ANDROID_HOME,
# JAVA_HOME or other SDK-location assumptions.
APKTOOL = "apktool"
AAPT2 = "aapt2"
ZIPALIGN = "zipalign"
APKSIGNER = "apksigner"
D8 = "d8"
KEYTOOL = "keytool"
JAVA = "java"

# --------------------------------------------------------------------- signing
# Signing always uses a per-machine debug key generated on first use.
DEBUG_KEYSTORE = PATCHER_DIR / ".debug-recast.jks"
DEBUG_ALIAS = "recast-debug"
DEBUG_PASS = "recastdebug"  # noqa: S105  # nosec B105 -- throwaway local key


def signing_config() -> tuple[Path, str, str, str]:
    """(keystore, alias, ks-pass-spec, key-pass-spec) for apksigner.

    Generates the debug keystore on first use via keytool from PATH.
    """
    import subprocess  # nosec B404 -- keytool from PATH, never shell

    if not DEBUG_KEYSTORE.is_file():
        print("==> generating local debug signing key (one-time, no setup needed)")
        r = subprocess.run(  # noqa: S603  # nosec B603 -- fixed keytool argv
            [
                KEYTOOL,
                "-genkeypair",
                "-keystore",
                str(DEBUG_KEYSTORE),
                "-alias",
                DEBUG_ALIAS,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "3650",
                "-storepass",
                DEBUG_PASS,
                "-keypass",
                DEBUG_PASS,
                "-dname",
                "CN=RecastDebug",
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode:
            raise RuntimeError(f"debug key generation failed: {r.stderr[-500:]}")
    return DEBUG_KEYSTORE, DEBUG_ALIAS, f"pass:{DEBUG_PASS}", f"pass:{DEBUG_PASS}"


# ------------------------------------------------------- ad / SDK package sets
# Trees deleted by the ads module. com/applovin is a special case: the shadow
# sub-tree is the app's live HTTP stack and must be preserved.
DELETED_SDK_TREES = (
    "com/inmobi",
    "com/fyber",
    "com/pubmatic",
    "com/google/android/gms/ads",
    "com/google/android/ump",
    "com/amazon/aps",
    "com/amazon/device/ads",
    "com/applovin",  # minus com/applovin/shadow -- see KEEP_TREES
)
KEEP_TREES = (
    "com/applovin/shadow",
    "com/bambuna",
    "androidx",
    "kotlin",
    "kotlinx",
    "com/google/firebase/messaging",
    "com/google/firebase/components",
    "com/google/firebase/common",
    "com/google/firebase/iid",
    "com/google/android/gms/auth",
    "com/google/api/services/drive",
    "com/google/api/client",
    "net/qiujuer/genius/blur",
    "org/vinuxproject/sonic",
)
# Namespaces whose types our patches delete, and which surviving code may
# therefore still reference. A type in one of these that resolves to no file
# in the tree MUST be replaced by a shim or ART throws
# NoClassDefFoundError / IncompatibleClassChangeError at launch.
#
# Single source of truth for the shim layer (audit + ShimPatch read it).
SHIM_NAMESPACES = (
    "com/applovin",  # shadow sub-tree excluded; it is kept
    "com/fyber",
    "com/inmobi",
    "com/pubmatic",
    "com/google/android/gms/ads",
    "com/google/android/ump",
    "com/amazon/aps",
    "com/amazon/device/ads",
    "com/google/firebase/analytics",
    "com/google/firebase/crashlytics",
)

# Suppressed telemetry / ad-serving endpoints.
BLOCKED_ENDPOINTS = (
    "ping_user.php",
    "update_podcast_stats.php",
    "update_playback_statistics.php",
    "update_categories_stats.php",
    "update_iha_stats.php",
    "update_curatedList_stats.php",
    "update_adCampaign_stats.php",
    "track_3rdparty_search.php",
    "get_podcast_stats.php",
    "reset_user_registrations.php",
    "get_iha.php",
    "get_adCampaign.php",
    "get_APS.php",
)

# Backend paths that must survive (functional / user-initiated).
KEPT_ENDPOINTS = (
    "post_websub_urls.php",
    "notify_rss_redirect.php",
    "submitpodcast.php",
    "submit_radio_catalog.php",
    "flagContent.php",
    "get_podcast_server_id.php",
    "post_review.php",
    "edit_review.php",
    "delete_review.php",
    "delete_user_reviews.php",
    "flag_review.php",
)

# ad-SDK literals that must not survive into the built APK.
AD_LITERALS = (
    "w8i12H9nSUHNhZb4NGvt-5KFuiDPRvHyUSh6O_6Tc9v2Tp4fxCeeAbAQZD_iIn8Vt1TSd7zEtc437oHcd_z5Ls",
    "a124058d-8cc9-47b5-b58f-dc8ffbbb7652",
    "de3fe86d-fd1d-4e63-bc52-e9175d7ea5f1",
    "ca-app-pub-4909759247131122~8502572498",
)

# assets that are functional and must NOT be deleted (measured smali refs > 0)
FUNCTIONAL_ASSETS = ("help.css", "android.css", "dsa_page.html")

# com/applovin/shadow/** is the live HTTP stack and must survive intact
# (424 files on both pins; asserted exactly).
SHADOW_PRESERVED = 424


_COLLISION_RE = re.compile(r"\.\d+$")


def strip_collision_suffix(stem: str) -> str:
    """Strip apktool's case-collision suffix: ej.1 -> ej.

    Obfuscated SDKs reuse names across cases (720 such pairs in the pristine
    tree). Apktool decodes the second as `ej.1.smali`, whose class is still
    `Lej;` -- a dot-digit suffix can never be part of a real class simple
    name, so stripping is unambiguous. Every place that derives a descriptor
    from a path must use this, or phantom classes (Lej.1) appear while the
    real ones (Lej) look missing.
    """
    return _COLLISION_RE.sub("", stem)


def descriptor_for(root: Path, path: Path) -> str:
    """Type descriptor for a smali file under a dex root (collision-aware)."""
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    parts[-1] = strip_collision_suffix(parts[-1])
    return "L" + "/".join(parts) + ";"
