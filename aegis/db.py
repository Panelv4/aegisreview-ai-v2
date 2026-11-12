"""Database models. SQLite by default; PostgreSQL via DATABASE_URL."""

from __future__ import annotations

import enum
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("owner_id", "slug", name="uq_project_owner_slug"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="projects")
    scans = relationship(
        "Scan", back_populates="project", cascade="all, delete-orphan", order_by="Scan.created_at.desc()"
    )

    @property
    def latest_scan(self) -> "Scan | None":
        return self.scans[0] if self.scans else None


class Scan(Base):
    """One analysis run over a snippet, file, archive or directory."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)

    target: Mapped[str] = mapped_column(String(512))          # filename / repo / "snippet"
    source_kind: Mapped[str] = mapped_column(String(32), default="snippet")  # snippet|upload|repo
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.COMPLETE)

    score: Mapped[int] = mapped_column(Integer, default=100)
    grade: Mapped[str] = mapped_column(String(4), default="A+")
    verdict: Mapped[str] = mapped_column(String(64), default="Clean")
    risk_points: Mapped[float] = mapped_column(Integer, default=0)
    n_critical: Mapped[int] = mapped_column(Integer, default=0)
    n_high: Mapped[int] = mapped_column(Integer, default=0)
    n_medium: Mapped[int] = mapped_column(Integer, default=0)
    n_low: Mapped[int] = mapped_column(Integer, default=0)
    n_info: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    engine_version: Mapped[str] = mapped_column(String(16), default="2.0.0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    project = relationship("Project", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan", order_by="Finding.id"
    )

    @property
    def counts(self) -> dict[str, int]:
        return {
            "critical": self.n_critical,
            "high": self.n_high,
            "medium": self.n_medium,
            "low": self.n_low,
            "info": self.n_info,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="high")
    cwe: Mapped[str] = mapped_column(String(32), default="")
    owasp: Mapped[str] = mapped_column(String(64), default="")
    file: Mapped[str] = mapped_column(String(512), default="snippet")
    language: Mapped[str] = mapped_column(String(32), default="unknown")
    line: Mapped[int] = mapped_column(Integer, default=1)
    column: Mapped[int] = mapped_column(Integer, default=1)
    code: Mapped[str] = mapped_column(Text, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    why: Mapped[str] = mapped_column(Text, default="")
    fix_hint: Mapped[str] = mapped_column(Text, default="")
    fix_example: Mapped[str] = mapped_column(Text, default="")
    vuln_example: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(32), index=True, default="")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    references_json: Mapped[str] = mapped_column(Text, default="[]")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")

    # triage state (survives rescans via fingerprint)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open|fixed|ignored|false-positive
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")

    @property
    def tags(self) -> list[str]:
        try:
            return json.loads(self.tags_json or "[]")
        except json.JSONDecodeError:
            return []

    @property
    def references(self) -> list[str]:
        try:
            return json.loads(self.references_json or "[]")
        except json.JSONDecodeError:
            return []

    @property
    def evidence(self) -> list[dict]:
        try:
            return json.loads(self.evidence_json or "[]")
        except json.JSONDecodeError:
            return []


# --------------------------------------------------------------------------- #
# engine / session
# --------------------------------------------------------------------------- #
_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
