"""Core data structures returned by the analysis engine."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any

# A finding we are not confident about must not move the score as much as a
# confirmed one; otherwise a hint and a proven RCE look identical.
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.7, "low": 0.3}

SEVERITY_WEIGHT = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.0,
}
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Evidence:
    """A taint trace or contextual line that justifies a finding."""

    line: int
    code: str
    role: str  # "source" | "sink" | "context"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp: str
    file: str
    line: int
    column: int
    code: str
    message: str
    why: str
    fix_hint: str
    vuln_example: str
    fix_example: str
    language: str
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    # stable id: same rule + same code => same fingerprint, so a baseline survives edits
    fingerprint: str = ""
    redacted: bool = False

    @property
    def uid(self) -> str:
        return self.fingerprint or f"{self.rule_id}:{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["uid"] = self.uid
        return d


@dataclass
class FileReport:
    path: str
    language: str
    lines: int
    findings: list[Finding] = field(default_factory=list)
    skipped: str | None = None
    suppressed: int = 0

    @property
    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


@dataclass
class ScanResult:
    files: list[FileReport] = field(default_factory=list)
    duration_ms: int = 0
    rules_evaluated: int = 0
    engine_version: str = "2.0.0"
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for f in self.files:
            out.extend(f.findings)
        return out

    @property
    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    @property
    def scannable_files(self) -> list[FileReport]:
        return [f for f in self.files if not f.skipped]

    @property
    def total_lines(self) -> int:
        return sum(f.lines for f in self.scannable_files)

    # -- scoring -----------------------------------------------------------
    @property
    def risk_points(self) -> float:
        """Severity weight x confidence, summed across findings."""
        pts = 0.0
        for f in self.findings:
            pts += SEVERITY_WEIGHT[f.severity] * CONFIDENCE_FACTOR.get(f.confidence, 1.0)
        return round(pts, 2)

    @property
    def score(self) -> int:
        """0-100 security score. 100 = no findings at all."""
        pts = self.risk_points
        if pts <= 0:
            return 100
        # logarithmic damping: 10 pts -> ~74, 50 -> ~41, 200 -> ~15
        import math

        raw = 100.0 - 26.0 * math.log10(1.0 + pts)
        return max(0, min(100, int(round(raw))))

    @property
    def grade(self) -> str:
        s = self.score
        for cutoff, g in ((95, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"), (40, "E")):
            if s >= cutoff:
                return g
        return "F"

    @property
    def verdict(self) -> str:
        if self.counts["critical"]:
            return "Block release"
        if self.counts["high"]:
            return "Fix before merge"
        if self.counts["medium"]:
            return "Needs attention"
        if self.counts["low"] or self.counts["info"]:
            return "Minor cleanup"
        return "Clean"

    def top_risks(self, n: int = 5) -> list[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(self.findings, key=lambda f: (order[f.severity], f.file, f.line))[:n]

    def rule_breakdown(self) -> list[dict[str, Any]]:
        agg: dict[str, dict[str, Any]] = {}
        for f in self.findings:
            row = agg.setdefault(
                f.rule_id,
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "cwe": f.cwe,
                    "count": 0,
                    "files": set(),
                },
            )
            row["count"] += 1
            row["files"].add(f.file)
        out = []
        for row in agg.values():
            row["files"] = sorted(row["files"])[:3]
            out.append(row)
        order = {s: i for i, s in enumerate(SEVERITIES)}
        out.sort(key=lambda r: (order[r["severity"]], -r["count"]))
        return out

    def summary(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "risk_points": self.risk_points,
            "counts": self.counts,
            "files_scanned": len(self.scannable_files),
            "files_skipped": len(self.files) - len(self.scannable_files),
            "lines_scanned": self.total_lines,
            "duration_ms": self.duration_ms,
            "rules_evaluated": self.rules_evaluated,
            "engine_version": self.engine_version,
        }


def fingerprint(rule_id: str, path: str, code: str) -> str:
    """Stable across line-number shifts: hash rule + normalised code line."""
    norm = " ".join(code.split())
    return hashlib.sha256(f"{rule_id}|{path}|{norm}".encode()).hexdigest()[:16]
