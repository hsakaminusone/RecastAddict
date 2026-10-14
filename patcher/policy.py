"""Authorized-target gate.

The patcher refuses to operate on anything but the pinned APK. This is both
good hygiene (patching the wrong artifact is the easiest way to get a bogus
result) and a deliberate boundary: the target is a third-party commercial app.
"""

from __future__ import annotations

import hashlib
import subprocess  # nosec B404 -- PATH tools, never shell
from dataclasses import dataclass
from pathlib import Path

from . import config


class PolicyError(RuntimeError):
    pass


@dataclass
class TargetInfo:
    sha256: str
    package: str
    version_name: str
    version_code: str
    signer_sha256: str
    signer_sha1: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
    if r.returncode != 0:
        raise PolicyError(f"{cmd[0]} failed: {r.stderr.strip()[:400]}")
    return r.stdout


def inspect(path: Path) -> TargetInfo:
    path = Path(path)
    if not path.is_file():
        raise PolicyError(f"input APK not found: {path}")
    info = TargetInfo("", "", "", "", "", "")
    info.sha256 = sha256_file(path)
    badging = _run([config.AAPT2, "dump", "badging", str(path)])
    for line in badging.splitlines():
        if line.startswith("package:"):
            for kv in line.split()[1:]:
                if kv.startswith("name="):
                    info.package = kv.split("=", 1)[1].strip("'")
                elif kv.startswith("versionName="):
                    info.version_name = kv.split("=", 1)[1].strip("'")
                elif kv.startswith("versionCode="):
                    info.version_code = kv.split("=", 1)[1].strip("'")
    certs = _run([config.APKSIGNER, "verify", "--print-certs", str(path)])
    for line in certs.splitlines():
        if "SHA-256 digest:" in line:
            info.signer_sha256 = line.split(":", 1)[1].strip().upper()
        elif "SHA-1 digest:" in line:
            info.signer_sha1 = line.split(":", 1)[1].strip().upper()
    return info


def check(path: Path) -> TargetInfo:
    """Raise PolicyError unless path is a supported pinned APK.

    Identification comes from the file itself (version + SHA-256 matched
    against the pins); package and signer are then enforced. Only the two
    supported builds pass.
    """
    info = inspect(Path(path))
    try:
        config.identify_pin(path)  # version + SHA-256 must match a supported pin
    except PolicyError as exc:
        raise PolicyError(f"refusing to patch unregistered target:\n  - {exc}") from exc
    problems = []
    if info.package != config.PACKAGE:
        problems.append(f"package {info.package!r} != {config.PACKAGE!r}")
    if info.signer_sha256 != config.SIGNER_SHA256:
        problems.append(f"signer SHA-256 {info.signer_sha256[:16]}... != pinned")
    if problems:
        raise PolicyError("refusing to patch unregistered target:\n  - " + "\n  - ".join(problems))
    return info
