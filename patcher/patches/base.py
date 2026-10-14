"""Patch contract.

Two tiers. A behaviour-tier failure is an ERROR; a size-tier uncertainty is a
WARNING. Size is a reward, never a requirement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Tier = Literal["behaviour", "size"]


@dataclass
class Anchor:
    """A resolved patch target. Resolution is structural, name is a hint."""

    id: str
    file: str
    descriptor: str
    method: str | None = None
    evidence: dict = field(default_factory=dict)
    confidence: str = "high"


@dataclass
class PatchResult:
    applied: int = 0
    already: int = 0
    files: list[Path] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    def note(self, msg: str) -> None:
        self.messages.append(msg)


class Patch(ABC):
    name: str = "?"
    tier: Tier = "behaviour"
    depends_on: tuple[str, ...] = ()
    ordered_after: tuple[str, ...] = ()

    @abstractmethod
    def resolve(self, ctx: Context) -> list[Anchor]:
        """Find targets against the PRISTINE tree. Raise AnchorError if absent."""

    @abstractmethod
    def apply(self, ctx: Context) -> PatchResult:
        """Apply edits. Must be idempotent."""

    @abstractmethod
    def verify(self, ctx: Context) -> list[str]:
        """Return human-readable proof that the intended invariants hold."""


class AnchorError(RuntimeError):
    """Raised when an anchor cannot be resolved. Fail loud, never guess."""


@dataclass
class Context:
    """Shared state handed to every patch."""

    app_src: Path
    anchors_dir: Path
    journal_dir: Path
    offline: bool = False  # dry-run: resolve and report, write nothing
    # the APK the tree was decoded from. Audits check this rather than the
    # configured default, so preflighting a scratch decode of either pinned
    # build reports the signer of the build actually in hand.
    source_apk: Path | None = None

    def module_journal(self, module: str) -> Path:
        return self.journal_dir / module
