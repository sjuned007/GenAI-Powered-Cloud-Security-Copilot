"""Service layer for the CloudGuardian scan pipeline."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from detection_engine import scan_inventory
from rwc_calculator import score_from_detection, rollup_by_resource


@dataclass
class ScanResult:
    """Unified output of detection + scoring + rollup."""
    issues: list[dict[str, Any]]
    resource_rollups: list[dict[str, Any]]


class ScanService:
    """Orchestrates end-to-end scan pipeline."""

    def execute_scan(self, inventory: list[dict[str, Any]]) -> ScanResult:
        raw_issues = scan_inventory(inventory)
        scored = score_from_detection(raw_issues)
        rollups = rollup_by_resource(scored)

        return ScanResult(
            issues=[asdict(s) for s in scored],
            resource_rollups=[asdict(r) for r in rollups],
        )
