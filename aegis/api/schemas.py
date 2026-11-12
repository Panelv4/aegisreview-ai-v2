"""Request/response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------- auth
class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    role: str
    created_at: datetime | None = None


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


# ---------------------------------------------------------------- scans
class SnippetIn(BaseModel):
    code: str = Field(min_length=1)
    filename: str = "snippet.py"
    language: str | None = None
    project_id: str | None = None


class RepoScanIn(BaseModel):
    url: str = Field(min_length=8, max_length=300)
    project_id: str | None = None
    include_tests: bool = False


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe: str
    owasp: str
    file: str
    language: str
    line: int
    column: int
    code: str
    message: str
    why: str
    fix_hint: str
    fix_example: str
    vuln_example: str
    fingerprint: str
    status: str
    note: str | None = None
    tags: list[str] = []
    references: list[str] = []
    evidence: list[dict[str, Any]] = []

    @classmethod
    def from_orm_finding(cls, f) -> "FindingOut":
        out = cls.model_validate(f)
        out.tags = f.tags
        out.references = f.references
        out.evidence = f.evidence
        return out


class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target: str
    source_kind: str
    status: str
    score: int
    grade: str
    verdict: str
    risk_points: float
    n_critical: int
    n_high: int
    n_medium: int
    n_low: int
    n_info: int
    files_scanned: int
    lines_scanned: int
    duration_ms: int
    engine_version: str
    created_at: datetime
    project_id: str | None = None


class ScanDetail(ScanSummary):
    findings: list[FindingOut] = []
    rule_breakdown: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}


class TriageIn(BaseModel):
    status: Literal["open", "fixed", "ignored", "false-positive"] | None = None
    note: str | None = None


# ---------------------------------------------------------------- projects
class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None
    language: str | None = None


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    slug: str
    description: str | None
    language: str | None
    created_at: datetime
    latest_score: int | None = None
    latest_grade: str | None = None
    scan_count: int = 0
    open_findings: int = 0


# ---------------------------------------------------------------- misc
class RuleOut(BaseModel):
    id: str
    title: str
    severity: str
    cwe: str
    owasp: str
    languages: list[str]
    why: str
    fix_hint: str
    tags: list[str]


class StatsOut(BaseModel):
    total_scans: int
    avg_score: int
    trend: list[dict[str, Any]]
    by_severity: dict[str, int]
    top_rules: list[dict[str, Any]]
    languages: dict[str, int]
    rules_available: int
    files_scanned: int
