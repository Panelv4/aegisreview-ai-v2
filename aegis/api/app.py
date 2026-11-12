"""FastAPI application: JSON API + static dashboard."""

from __future__ import annotations

import io
import json
import time
import re
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..db import Finding, Project, Scan, ScanStatus, SessionLocal, User, UserRole, init_db, utcnow
from ..engine import rules as rule_registry
from ..engine.analyzer import ENGINE_VERSION, analyze_source, scan_path
from ..engine.exporters import export as export_report
from ..engine.models import ScanResult
from ..engine.policy import Policy
from ..engine.rules import RULES
from .. import repofetch
from ..security import (
    AdminUser,
    CurrentUser,
    Db,
    OptionalUser,
    access_token,
    decode,
    hash_password,
    refresh_token,
    verify_password,
)
from .schemas import (
    RepoScanIn,
    FindingOut,
    LoginIn,
    ProjectIn,
    ProjectOut,
    RefreshIn,
    RegisterIn,
    RuleOut,
    ScanDetail,
    ScanSummary,
    SnippetIn,
    StatsOut,
    TokenOut,
    TriageIn,
    UserOut,
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    if settings.SEED_DEMO:
        seed_demo()
    yield


app = FastAPI(
    title=f"{settings.PROJECT_NAME} API",
    version=settings.VERSION,
    lifespan=lifespan,
    description=(
        f"Deterministic static security analysis: {len(rule_registry.RULES)} rules, "
        "taint traces, risk scoring, SARIF export and a CI policy gate. "
        "No LLM required."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "project"


def persist_scan(db: Session, result: ScanResult, *, target: str, kind: str,
                 owner: User, project_id: str | None = None) -> Scan:
    c = result.counts
    scan = Scan(
        owner_id=owner.id,
        project_id=project_id,
        target=target[:512],
        source_kind=kind,
        status=ScanStatus.COMPLETE,
        score=result.score,
        grade=result.grade,
        verdict=result.verdict,
        risk_points=int(result.risk_points),
        n_critical=c["critical"], n_high=c["high"], n_medium=c["medium"],
        n_low=c["low"], n_info=c["info"],
        files_scanned=len(result.scannable_files),
        lines_scanned=result.total_lines,
        duration_ms=result.duration_ms,
        engine_version=ENGINE_VERSION,
    )
    db.add(scan)
    db.flush()

    for f in result.findings:
        db.add(
            Finding(
                scan_id=scan.id,
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                cwe=f.cwe,
                owasp=f.owasp,
                file=f.file,
                language=f.language,
                line=f.line,
                column=f.column,
                code=f.code,
                message=f.message,
                why=f.why,
                fix_hint=f.fix_hint,
                fix_example=f.fix_example,
                vuln_example=f.vuln_example,
                fingerprint=f.fingerprint,
                tags_json=json.dumps(f.tags),
                references_json=json.dumps(f.references),
                evidence_json=json.dumps(
                    [{"line": e.line, "code": e.code, "role": e.role} for e in f.evidence]
                ),
            )
        )
    db.commit()
    db.refresh(scan)
    return scan


def rebuild_result(scan: Scan) -> ScanResult:
    """Rehydrate an engine ScanResult from a stored scan (for re-export)."""
    from ..engine.models import FileReport, Finding as EFinding, Evidence

    files: dict[str, FileReport] = {}
    for f in scan.findings:
        fr = files.setdefault(f.file, FileReport(path=f.file, language=f.language, lines=0))
        fr.findings.append(
            EFinding(
                rule_id=f.rule_id, title=f.title, severity=f.severity,
                confidence=f.confidence, cwe=f.cwe, owasp=f.owasp, file=f.file,
                line=f.line, column=f.column, code=f.code, message=f.message,
                why=f.why, fix_hint=f.fix_hint, vuln_example=f.vuln_example,
                fix_example=f.fix_example, language=f.language,
                tags=f.tags, references=f.references,
                evidence=[Evidence(**e) for e in f.evidence],
                fingerprint=f.fingerprint,
            )
        )
    result = ScanResult(files=list(files.values()), duration_ms=scan.duration_ms,
                        rules_evaluated=len(RULES), engine_version=scan.engine_version)
    return result


def result_to_transient_detail(result: ScanResult, target: str) -> ScanDetail:
    """Build a ScanDetail from an in-memory result (no persistence)."""
    c = result.counts
    return ScanDetail(
        id="",
        target=target,
        source_kind="snippet",
        status="complete",
        score=result.score, grade=result.grade, verdict=result.verdict,
        risk_points=result.risk_points,
        n_critical=c["critical"], n_high=c["high"], n_medium=c["medium"],
        n_low=c["low"], n_info=c["info"],
        files_scanned=len(result.scannable_files), lines_scanned=result.total_lines,
        duration_ms=result.duration_ms, engine_version=ENGINE_VERSION,
        created_at=utcnow(),
        findings=[
            FindingOut(
                id=f.uid, rule_id=f.rule_id, title=f.title, severity=f.severity,
                confidence=f.confidence, cwe=f.cwe, owasp=f.owasp, file=f.file,
                language=f.language, line=f.line, column=f.column, code=f.code,
                message=f.message, why=f.why, fix_hint=f.fix_hint,
                fix_example=f.fix_example, vuln_example=f.vuln_example,
                fingerprint=f.fingerprint, status="open", note=None,
                tags=f.tags, references=f.references,
                evidence=[{"line": e.line, "code": e.code, "role": e.role} for e in f.evidence],
            )
            for f in result.findings
        ],
        rule_breakdown=result.rule_breakdown(),
        meta={"persisted": False},
    )


def scan_to_detail(scan: Scan) -> ScanDetail:
    result = rebuild_result(scan)
    return ScanDetail(
        **ScanSummary.model_validate(scan).model_dump(),
        findings=[FindingOut.from_orm_finding(f) for f in scan.findings],
        rule_breakdown=result.rule_breakdown(),
        meta={"counts": scan.counts},
    )


def owned_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or (scan.owner_id != user.id and user.role != UserRole.ADMIN):
        raise HTTPException(404, "Scan not found")
    return scan


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
@app.post("/api/auth/register", response_model=TokenOut, status_code=201, tags=["auth"])
def register(payload: RegisterIn, db: Db):
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(403, "Registration is disabled")
    if db.query(User).filter(func.lower(User.email) == payload.email.lower()).first():
        raise HTTPException(409, "An account with this email already exists")
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name.strip(),
        hashed_password=hash_password(payload.password),
    )
    # first user becomes admin so a fresh install is manageable
    if db.query(User).count() == 0:
        user.role = UserRole.ADMIN
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenOut(
        access_token=access_token(user), refresh_token=refresh_token(user),
        user=UserOut.model_validate(user),
    )


@app.post("/api/auth/login", response_model=TokenOut, tags=["auth"])
def login(payload: LoginIn, db: Db):
    user = db.query(User).filter(func.lower(User.email) == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(401, "Incorrect email or password")
    if not user.is_active:
        raise HTTPException(403, "This account is disabled")
    return TokenOut(
        access_token=access_token(user), refresh_token=refresh_token(user),
        user=UserOut.model_validate(user),
    )


@app.post("/api/auth/refresh", response_model=TokenOut, tags=["auth"])
def refresh(payload: RefreshIn, db: Db):
    data = decode(payload.refresh_token, expect="refresh")
    if not data:
        raise HTTPException(401, "Invalid or expired refresh token")
    user = db.get(User, data["sub"])
    if not user or not user.is_active:
        raise HTTPException(401, "Invalid or expired refresh token")
    return TokenOut(
        access_token=access_token(user), refresh_token=refresh_token(user),
        user=UserOut.model_validate(user),
    )


@app.get("/api/auth/me", response_model=UserOut, tags=["auth"])
def me(user: CurrentUser):
    return UserOut.model_validate(user)


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
@app.post("/api/scans/snippet", response_model=ScanDetail, tags=["scans"])
def scan_snippet(payload: SnippetIn, db: Db, user: OptionalUser):
    """Scan a code snippet. Works without auth (ephemeral demo scans go to a guest user)."""
    clean = payload.code[:400_000]
    name = payload.filename or "snippet.py"
    report = analyze_source(clean, name, payload.language)
    result = ScanResult(files=[report], duration_ms=0, rules_evaluated=len(RULES),
                        engine_version=ENGINE_VERSION)
    if user is None:
        # anonymous: return the report without writing anything
        return result_to_transient_detail(result, name)
    scan = persist_scan(db, result, target=name, kind="snippet",
                        owner=user, project_id=payload.project_id)
    return scan_to_detail(scan)


@app.post("/api/scans/upload", response_model=ScanDetail, tags=["scans"])
async def scan_upload(
    db: Db,
    user: CurrentUser,
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
):
    """Upload a single file or a .zip archive of a project."""
    data = await file.read()
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024 * (10 if (file.filename or "").endswith(".zip") else 1)
    if len(data) > limit:
        raise HTTPException(413, f"File exceeds the {limit // (1024*1024)} MB limit")

    name = (file.filename or "upload.txt").split("/")[-1]
    if name.lower().endswith(".zip"):
        tmp = Path(tempfile.mkdtemp(prefix="aegis_"))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.infolist():
                    target = (tmp / member.filename).resolve()
                    if not str(target).startswith(str(tmp.resolve())):
                        continue  # zip-slip guard
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if member.file_size > settings.MAX_REPO_MB * 1024 * 1024:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
            result = scan_path(tmp, include_tests=False)
            kind, target_name = "archive", name
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")
        report = analyze_source(text, name)
        result = ScanResult(files=[report], rules_evaluated=len(RULES), engine_version=ENGINE_VERSION)
        kind, target_name = "upload", name

    scan = persist_scan(db, result, target=target_name, kind=kind, owner=user, project_id=project_id)
    return scan_to_detail(scan)


# Cloning is the one expensive operation we expose, so cap it per user.
_REPO_HOURLY_LIMIT = 10
_repo_calls: dict[str, list[float]] = {}


def _throttle_repo(user_id: str) -> None:
    now = time.time()
    calls = [t for t in _repo_calls.get(user_id, []) if now - t < 3600]
    if len(calls) >= _REPO_HOURLY_LIMIT:
        raise HTTPException(
            429,
            f"Repository scan limit reached ({_REPO_HOURLY_LIMIT}/hour). Try again later.",
        )
    calls.append(now)
    _repo_calls[user_id] = calls


@app.post("/api/scans/repo", response_model=ScanDetail, tags=["scans"])
def scan_repo(payload: RepoScanIn, db: Db, user: CurrentUser):
    """Shallow-clone a public repository from an allowlisted forge and analyse it."""
    _throttle_repo(user.id)
    try:
        info = repofetch.clone(payload.url)
    except repofetch.RepoError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = scan_path(
            info.path, include_tests=payload.include_tests, include_docs=False
        )
        scan = persist_scan(
            db, result, target=info.label, kind="repo", owner=user,
            project_id=payload.project_id,
        )
        detail = scan_to_detail(scan)
        detail.meta = {
            **(detail.meta or {}),
            "repo": {
                "url": info.url,
                "host": info.host,
                "owner": info.owner,
                "name": info.name,
                "size_mb": info.size_mb,
                "files_in_clone": info.files,
            },
        }
        return detail
    finally:
        repofetch.cleanup(info)


@app.get("/api/scans", response_model=list[ScanSummary], tags=["scans"])
def list_scans(db: Db, user: CurrentUser, project_id: str | None = None, limit: int = 50):
    q = db.query(Scan).filter(Scan.owner_id == user.id)
    if project_id:
        q = q.filter(Scan.project_id == project_id)
    return [ScanSummary.model_validate(s) for s in q.order_by(Scan.created_at.desc()).limit(limit)]


@app.get("/api/scans/{scan_id}", response_model=ScanDetail, tags=["scans"])
def get_scan(scan_id: str, db: Db, user: CurrentUser):
    return scan_to_detail(owned_scan(db, scan_id, user))


@app.delete("/api/scans/{scan_id}", status_code=204, tags=["scans"])
def delete_scan(scan_id: str, db: Db, user: CurrentUser):
    scan = owned_scan(db, scan_id, user)
    db.delete(scan)
    db.commit()


@app.patch("/api/findings/{finding_id}", tags=["scans"])
def triage_finding(finding_id: str, payload: TriageIn, db: Db, user: CurrentUser):
    f = db.get(Finding, finding_id)
    if not f or f.scan.owner_id != user.id:
        raise HTTPException(404, "Finding not found")
    if payload.status is not None:
        f.status = payload.status
    if payload.note is not None:
        f.note = payload.note
    db.commit()
    return {"ok": True, "status": f.status, "note": f.note}


@app.get("/api/scans/{scan_id}/export", tags=["scans"])
def export_scan(scan_id: str, db: Db, user: CurrentUser, fmt: str = Query("html")):
    scan = owned_scan(db, scan_id, user)
    content, media = export_report(rebuild_result(scan), fmt, title=f"AegisReview — {scan.target}")
    ext = {"sarif": "sarif", "json": "json", "markdown": "md", "md": "md"}.get(fmt, "html")
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="aegis-{scan.id[:8]}.{ext}"'},
    )


# --------------------------------------------------------------------------- #
# CI gate
# --------------------------------------------------------------------------- #
@app.post("/api/ci/gate", tags=["ci"])
async def ci_gate(
    db: Db,
    file: UploadFile = File(...),
    max_critical: int = Form(0),
    max_high: int = Form(0),
    max_medium: int = Form(10),
    min_score: int = Form(0),
):
    """Scan an uploaded file/archive and return a pass/fail decision (HTTP 409 on fail)."""
    data = await file.read()
    name = (file.filename or "ci.bin").split("/")[-1]
    if name.lower().endswith(".zip"):
        tmp = Path(tempfile.mkdtemp(prefix="aegis_ci_"))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for m in zf.infolist():
                    t = (tmp / m.filename).resolve()
                    if str(t).startswith(str(tmp.resolve())) and not m.is_dir():
                        t.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(m) as src, open(t, "wb") as dst:
                            shutil.copyfileobj(src, dst)
            result = scan_path(tmp, include_tests=False)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")
        result = ScanResult(files=[analyze_source(text, name)], rules_evaluated=len(RULES))

    policy = Policy(max_critical=max_critical, max_high=max_high,
                    max_medium=max_medium, min_score=min_score)
    ok, reasons = policy.evaluate(result)
    body = {
        "passed": ok,
        "reasons": reasons,
        "summary": result.summary(),
        "policy": policy.to_dict(),
        "top_risks": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
             "file": f.file, "line": f.line}
            for f in result.top_risks(5)
        ],
        "sarif": None,
    }
    return JSONResponse(body, status_code=200 if ok else 409)


# --------------------------------------------------------------------------- #
# projects
# --------------------------------------------------------------------------- #
@app.get("/api/projects", response_model=list[ProjectOut], tags=["projects"])
def list_projects(db: Db, user: CurrentUser):
    projects = (
        db.query(Project).filter(Project.owner_id == user.id)
        .order_by(Project.created_at.desc()).all()
    )
    out = []
    for p in projects:
        latest = db.query(Scan).filter(Scan.project_id == p.id).order_by(Scan.created_at.desc()).first()
        open_findings = (
            db.query(func.count(Finding.id)).join(Scan)
            .filter(Scan.project_id == p.id, Finding.status == "open").scalar() or 0
        )
        item = ProjectOut.model_validate(p)
        item.latest_score = latest.score if latest else None
        item.latest_grade = latest.grade if latest else None
        item.scan_count = db.query(func.count(Scan.id)).filter(Scan.project_id == p.id).scalar() or 0
        item.open_findings = open_findings
        out.append(item)
    return out


@app.post("/api/projects", response_model=ProjectOut, status_code=201, tags=["projects"])
def create_project(payload: ProjectIn, db: Db, user: CurrentUser):
    slug = slugify(payload.name)
    if db.query(Project).filter(Project.owner_id == user.id, Project.slug == slug).first():
        raise HTTPException(409, "You already have a project with that name")
    p = Project(name=payload.name.strip(), slug=slug,
                description=payload.description, language=payload.language, owner_id=user.id)
    db.add(p)
    db.commit()
    db.refresh(p)
    return ProjectOut.model_validate(p)


@app.delete("/api/projects/{project_id}", status_code=204, tags=["projects"])
def delete_project(project_id: str, db: Db, user: CurrentUser):
    p = db.get(Project, project_id)
    if not p or p.owner_id != user.id:
        raise HTTPException(404, "Project not found")
    db.delete(p)
    db.commit()


# --------------------------------------------------------------------------- #
# stats, rules, admin
# --------------------------------------------------------------------------- #
@app.get("/api/stats", response_model=StatsOut, tags=["insights"])
def stats(db: Db, user: CurrentUser):
    scans = db.query(Scan).filter(Scan.owner_id == user.id).order_by(Scan.created_at.asc()).all()
    trend = [
        {"id": s.id, "date": s.created_at.isoformat(), "score": s.score,
         "target": s.target, "critical": s.n_critical, "high": s.n_high}
        for s in scans[-30:]
    ]
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    langs: dict[str, int] = {}
    top: dict[str, dict] = {}
    for s in scans:
        for k in sev:
            sev[k] += getattr(s, f"n_{k}")
        for f in s.findings:
            langs[f.language] = langs.get(f.language, 0) + 1
            row = top.setdefault(f.rule_id, {"rule_id": f.rule_id, "title": f.title, "count": 0})
            row["count"] += 1
    return StatsOut(
        total_scans=len(scans),
        avg_score=int(round(sum(s.score for s in scans) / len(scans))) if scans else 100,
        trend=trend,
        by_severity=sev,
        top_rules=sorted(top.values(), key=lambda r: -r["count"])[:8],
        languages=langs,
        rules_available=len(RULES),
        files_scanned=sum(s.files_scanned for s in scans),
    )


@app.get("/api/rules", response_model=list[RuleOut], tags=["insights"])
def list_rules():
    return [
        RuleOut(
            id=r.id, title=r.title, severity=r.severity, cwe=r.cwe, owasp=r.owasp,
            languages=list(r.languages), why=r.why, fix_hint=r.fix_hint, tags=list(r.tags),
        )
        for r in RULES
    ]


@app.get("/api/admin/overview", tags=["admin"])
def admin_overview(db: Db, _: AdminUser):
    return {
        "users": db.query(func.count(User.id)).scalar(),
        "scans": db.query(func.count(Scan.id)).scalar(),
        "findings": db.query(func.count(Finding.id)).scalar(),
        "avg_score": round(db.query(func.avg(Scan.score)).scalar() or 100, 1),
        "engine_version": ENGINE_VERSION,
        "rules": len(RULES),
    }


@app.get("/api/health", tags=["meta"])
def health():
    return {
        "status": "ok",
        "version": settings.VERSION,
        "engine": ENGINE_VERSION,
        "rules": len(RULES),
        "time": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------- #
# demo user
# --------------------------------------------------------------------------- #
DEMO_EMAIL = "demo@aegis.dev"
DEMO_PASSWORD = "aegis-demo-2024"


def seed_demo() -> None:
    """Create a demo account with one analysed project so the UI is never empty."""
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == DEMO_EMAIL).first():
            return
        user = User(email=DEMO_EMAIL, full_name="Demo Analyst",
                    hashed_password=hash_password(DEMO_PASSWORD), role=UserRole.ADMIN)
        db.add(user)
        db.commit()
        db.refresh(user)

        project = Project(name="Vulnerable Shop", slug="vulnerable-shop", owner_id=user.id,
                          description="Reference Flask storefront used to benchmark the engine.")
        db.add(project)
        db.commit()
        db.refresh(project)

        sample = BASE_DIR.parent / "samples" / "vulnerable-app"
        if sample.exists():
            result = scan_path(sample)
            persist_scan(db, result, target="samples/vulnerable-app",
                         kind="archive", owner=user, project_id=project.id)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# static dashboard
# --------------------------------------------------------------------------- #
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")
