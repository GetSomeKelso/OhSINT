"""Report generation utilities for OSINT Orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

from src.models import ReconReport


def save_report(report: ReconReport, output_dir: Path, fmt: str = "all") -> None:
    """Save a ReconReport in the specified format(s)."""
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt in ("json", "all"):
        (output_dir / "report.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )

    if fmt in ("md", "all"):
        (output_dir / "report.md").write_text(
            report.to_markdown(), encoding="utf-8"
        )

    if fmt in ("html", "all"):
        (output_dir / "report.html").write_text(
            report.to_html(), encoding="utf-8"
        )


def load_report(path: Path) -> ReconReport:
    """Load a ReconReport from a JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return ReconReport.model_validate(data)
