from patcher.patches.base import Patch
from patcher.patches.premium import PremiumPatch
from patcher.patches.security_behavior import AdsPatch, SecurityBehaviorPatch
from patcher.patches.shrink import ShimPatch, ShrinkPatch
from patcher.patches.telemetry import TelemetryPatch

REGISTRY: list[type[Patch]] = [
    PremiumPatch,
    SecurityBehaviorPatch,
    AdsPatch,
    TelemetryPatch,
    ShrinkPatch,
    ShimPatch,
]


def order_patches() -> list[type[Patch]]:
    by_name = {c.name: c for c in REGISTRY}
    seen: list[str] = []

    def visit(name: str, stack: tuple[str, ...] = ()) -> None:
        if name in seen:
            return
        if name in stack:
            raise ValueError(f"patch dependency cycle: {' -> '.join((*stack, name))}")
        c = by_name[name]
        for d in c.depends_on:
            visit(d, (*stack, name))
        for a in c.ordered_after:
            if a in by_name and a not in seen:
                visit(a, (*stack, name))
        seen.append(name)

    for c in REGISTRY:
        visit(c.name)
    return [by_name[n] for n in seen if n in by_name]
