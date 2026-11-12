"""
CI policy gate.

A scanner that only prints findings does not change behaviour. This module turns
a scan into a pass/fail decision with an explicit, reviewable budget:

    policy = Policy(max_critical=0, max_high=0, max_medium=5, max_score_drop=0)
    allowed, reasons = policy.evaluate(result, baseline=previous_scan)

Exit code 1 from the CLI when `allowed` is False, so a pipeline can block a merge.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import SEVERITIES, ScanResult


@dataclass
class Policy:
    # absolute caps
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 10
    max_low: int | None = None
    min_score: int = 0
    # regression gate: fail if the score drops more than this vs. the baseline
    max_score_drop: int | None = None
    # only gate on these paths (glob-ish prefix match); empty = everything
    include_paths: tuple[str, ...] = ()
    fail_on_confidence: tuple[str, ...] = ("high", "medium")

    def evaluate(
        self, result: ScanResult, baseline_score: int | None = None
    ) -> tuple[bool, list[str]]:
        findings = [
            f
            for f in result.findings
            if not self.include_paths
            or any(f.file.startswith(p) for p in self.include_paths)
        ]
        gated = [f for f in findings if f.confidence in self.fail_on_confidence]
        counts = {s: 0 for s in SEVERITIES}
        for f in gated:
            counts[f.severity] += 1

        reasons: list[str] = []
        if counts["critical"] > self.max_critical:
            reasons.append(
                f"{counts['critical']} critical finding(s) exceed the budget of {self.max_critical}"
            )
        if counts["high"] > self.max_high:
            reasons.append(
                f"{counts['high']} high finding(s) exceed the budget of {self.max_high}"
            )
        if counts["medium"] > self.max_medium:
            reasons.append(
                f"{counts['medium']} medium finding(s) exceed the budget of {self.max_medium}"
            )
        if self.max_low is not None and counts["low"] > self.max_low:
            reasons.append(f"{counts['low']} low finding(s) exceed the budget of {self.max_low}")
        if result.score < self.min_score:
            reasons.append(f"score {result.score} is below the required minimum {self.min_score}")
        if (
            self.max_score_drop is not None
            and baseline_score is not None
            and baseline_score - result.score > self.max_score_drop
        ):
            reasons.append(
                f"score dropped {baseline_score - result.score} points "
                f"({baseline_score} -> {result.score}); allowed drop is {self.max_score_drop}"
            )
        return (not reasons), reasons

    def to_dict(self) -> dict:
        return {
            "max_critical": self.max_critical,
            "max_high": self.max_high,
            "max_medium": self.max_medium,
            "max_low": self.max_low,
            "min_score": self.min_score,
            "max_score_drop": self.max_score_drop,
            "include_paths": list(self.include_paths),
            "fail_on_confidence": list(self.fail_on_confidence),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        data = dict(data or {})
        if "include_paths" in data:
            data["include_paths"] = tuple(data["include_paths"])
        if "fail_on_confidence" in data:
            data["fail_on_confidence"] = tuple(data["fail_on_confidence"])
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


DEFAULT_POLICY = Policy()


@dataclass
class Baseline:
    """Fingerprints from a previously accepted scan — used to hide known issues."""

    fingerprints: set[str] = field(default_factory=set)
    score: int = 100

    @classmethod
    def from_findings(cls, findings: list[dict], score: int = 100) -> "Baseline":
        return cls(
            fingerprints={
                f.get("fingerprint") or f.get("uid", "") for f in findings if f
            },
            score=score,
        )

    def is_new(self, fingerprint: str) -> bool:
        return fingerprint not in self.fingerprints
