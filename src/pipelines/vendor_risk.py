"""Vendor / third-party risk assessment.

NOT a new toolchain — this runs the existing passive recon (PassiveFullPipeline)
against a vendor's domain, then re-frames the findings through a *risk-to-you*
lens: a graded scorecard instead of a bug-bounty finding list.

Bug bounty asks "what can I exploit?"  Vendor risk asks "should I trust this
counterparty?"  Same findings, different weighting and different consumer.

Authorization posture: assessing a counterparty you are evaluating is passive
recon of public data — no --authorization gate (same as osint_passive_full).

Scoring is opinionated-but-tunable: default category weights live in
configs/pipeline_defaults.yaml under `vendor_risk` and can be overridden.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.config import Config, DEFAULT_TIMEOUT
from src.models import IntelFinding, IntelType, ReconReport

console = Console()
logger = logging.getLogger("ohsint.pipeline.vendor_risk")


# Default rubric — overridable via configs/pipeline_defaults.yaml `vendor_risk`.
# Each category: which IntelTypes feed it, per-finding penalty, and a cap so one
# noisy category can't sink the whole grade on its own.
DEFAULT_RUBRIC = {
    "categories": {
        "breach_exposure": {
            "label": "Breach & credential exposure",
            "types": ["breach", "credential", "infostealer"],
            "per_finding": 8,
            "cap": 40,
            "weight": 1.0,
        },
        "secret_leakage": {
            "label": "Leaked secrets",
            "types": ["leaked_secret"],
            "per_finding": 10,
            "cap": 40,
            "weight": 1.0,
        },
        "attack_surface": {
            "label": "Exposed attack surface",
            "types": ["subdomain_takeover", "exposed_api_doc", "sensitive_file", "port_service"],
            "per_finding": 4,
            "cap": 30,
            "weight": 1.0,
        },
        "vulnerabilities": {
            "label": "Known vulnerabilities",
            "types": ["vulnerability"],
            "per_finding": 6,
            "cap": 30,
            "weight": 1.0,
        },
        "hygiene": {
            "label": "Hygiene & footprint",
            "types": ["js_endpoint", "dns_record", "technology"],
            "per_finding": 1,
            "cap": 15,
            "weight": 1.0,
        },
    },
    # Severity multipliers applied per-finding when a 'severity' tag/raw_data is present
    "severity_multipliers": {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.25,
    },
    # Score → letter grade thresholds (score is 100 minus total penalty)
    "grades": [
        {"min": 90, "grade": "A"},
        {"min": 80, "grade": "B"},
        {"min": 70, "grade": "C"},
        {"min": 60, "grade": "D"},
        {"min": 0, "grade": "F"},
    ],
}


class VendorRiskPipeline:
    """Runs passive recon against a vendor, scores findings as a risk scorecard."""

    def __init__(
        self,
        config: Optional[Config] = None,
        timeout: int = DEFAULT_TIMEOUT,
        verbose: bool = False,
    ):
        self.config = config or Config()
        self.timeout = timeout
        self.verbose = verbose
        self.rubric = self._load_rubric()

    def _load_rubric(self) -> dict:
        """Merge tunable overrides from pipeline_defaults.yaml over the defaults."""
        cfg = self.config.get_pipeline_config("vendor_risk") or {}
        rubric = {**DEFAULT_RUBRIC}
        if "categories" in cfg:
            rubric["categories"] = cfg["categories"]
        if "severity_multipliers" in cfg:
            rubric["severity_multipliers"] = cfg["severity_multipliers"]
        if "grades" in cfg:
            rubric["grades"] = cfg["grades"]
        return rubric

    def run(
        self,
        targets: list[str],
        output_dir: Path | None = None,
        skip_takeover: bool = False,
    ) -> ReconReport:
        """Run passive recon against the vendor, then attach a risk scorecard.

        Returns the merged ReconReport with a `vendor_risk` scorecard stashed in
        summary + resolved_target so renderers/CLI can display the grade.
        """
        from src.pipelines.passive_full import PassiveFullPipeline

        console.print(f"[bold green]Vendor risk assessment[/bold green] — {', '.join(targets)}")
        console.print("  [dim]Running passive recon, then scoring as risk scorecard...[/dim]\n")

        passive = PassiveFullPipeline(config=self.config, timeout=self.timeout, verbose=self.verbose)
        report = passive.run(targets, output_dir=output_dir, skip_takeover=skip_takeover)

        scorecard = self.score(report.findings)
        report.scan_profile = "vendor_risk"

        # Stash scorecard so save_report/markdown can surface it (string map only)
        report.resolved_target = report.resolved_target or {}
        report.resolved_target["vendor_risk_grade"] = scorecard["grade"]
        report.resolved_target["vendor_risk_score"] = str(scorecard["score"])
        report.summary["vendor_risk_score"] = scorecard["score"]

        self._print_scorecard(targets, scorecard)
        # Keep full scorecard accessible to callers (not persisted in the pydantic model)
        self.last_scorecard = scorecard
        return report

    def score(self, findings: list[IntelFinding]) -> dict:
        """Compute the risk scorecard from findings. Returns grade, score, breakdown."""
        cats = self.rubric["categories"]
        mults = self.rubric["severity_multipliers"]

        # type -> category lookup
        type_to_cat: dict[str, str] = {}
        for cat_key, spec in cats.items():
            for t in spec["types"]:
                type_to_cat[t] = cat_key

        breakdown = {
            k: {"label": v["label"], "count": 0, "penalty": 0.0}
            for k, v in cats.items()
        }

        for f in findings:
            cat_key = type_to_cat.get(f.type.value)
            if not cat_key:
                continue
            spec = cats[cat_key]
            sev = self._finding_severity(f)
            mult = mults.get(sev, 1.0)
            breakdown[cat_key]["count"] += 1
            breakdown[cat_key]["penalty"] += spec["per_finding"] * mult

        # Apply caps + category weight
        total_penalty = 0.0
        for cat_key, spec in cats.items():
            raw = breakdown[cat_key]["penalty"]
            capped = min(raw, spec["cap"]) * spec.get("weight", 1.0)
            breakdown[cat_key]["penalty"] = round(capped, 1)
            total_penalty += capped

        score = max(0, round(100 - total_penalty))
        grade = self._grade_for(score)

        # Top risks: highest-penalty categories with findings
        top = sorted(
            [b for b in breakdown.values() if b["count"] > 0],
            key=lambda b: b["penalty"],
            reverse=True,
        )

        return {
            "score": score,
            "grade": grade,
            "total_penalty": round(total_penalty, 1),
            "breakdown": breakdown,
            "top_risks": top[:3],
            "total_findings": len(findings),
        }

    def _finding_severity(self, f: IntelFinding) -> str:
        """Extract a severity label from a finding's raw_data or tags, default medium."""
        rd = f.raw_data or {}
        sev = str(rd.get("severity", "")).lower().strip()
        if sev in self.rubric["severity_multipliers"]:
            return sev
        for tag in f.tags:
            t = tag.lower().strip()
            if t in self.rubric["severity_multipliers"]:
                return t
        return "medium"

    def _grade_for(self, score: int) -> str:
        for band in sorted(self.rubric["grades"], key=lambda b: b["min"], reverse=True):
            if score >= band["min"]:
                return band["grade"]
        return "F"

    def _print_scorecard(self, targets: list[str], sc: dict) -> None:
        grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
        color = grade_color.get(sc["grade"], "white")
        console.print(f"\n[bold]Vendor Risk Scorecard — {', '.join(targets)}[/bold]")
        console.print(f"  Grade: [{color}]{sc['grade']}[/{color}]  (score {sc['score']}/100, "
                      f"{sc['total_findings']} findings)")
        console.print("  [dim]Category breakdown:[/dim]")
        for key, b in sc["breakdown"].items():
            if b["count"]:
                console.print(f"    • {b['label']}: {b['count']} findings → −{b['penalty']} pts")
        if sc["top_risks"]:
            console.print("  [bold]Top risk areas:[/bold]")
            for b in sc["top_risks"]:
                console.print(f"    [red]●[/red] {b['label']} (−{b['penalty']} pts)")

    def dry_run(self, targets: list[str]) -> list[dict]:
        """Vendor risk reuses the passive_full toolchain — defer to it for readiness."""
        from src.pipelines.passive_full import PassiveFullPipeline
        return PassiveFullPipeline(config=self.config).dry_run(targets)
