"""Auth: password hashing, JWT issue/verify, FastAPI dependencies."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

import bcrypt
from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal, User, UserRole

ALGORITHM = "HS256"


# --------------------------------------------------------------------------- #
# passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    # bcrypt silently ignores bytes past 72; truncate explicitly so behaviour is
    # predictable rather than surprising.
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #
def create_token(sub: str, kind: str, expires: timedelta, **claims: Any) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": sub, "type": kind, "iat": now, "exp": now + expires, **claims}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def access_token(user: User) -> str:
    return create_token(
        user.id, "access", timedelta(minutes=settings.ACCESS_TOKEN_MINUTES), role=user.role.value
    )


def refresh_token(user: User) -> str:
    return create_token(user.id, "refresh", timedelta(days=settings.REFRESH_TOKEN_DAYS))


def decode(token: str, expect: str = "access") -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != expect:
        return None
    return payload


# --------------------------------------------------------------------------- #
# dependencies
# --------------------------------------------------------------------------- #
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


Db = Annotated[Session, Depends(get_db)]

_CRED_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise _CRED_ERROR
    payload = decode(authorization.split(" ", 1)[1].strip())
    if not payload:
        raise _CRED_ERROR
    user = db.get(User, payload.get("sub", ""))
    if user is None or not user.is_active:
        raise _CRED_ERROR
    return user


def optional_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User | None:
    try:
        return current_user(authorization, db)
    except HTTPException:
        return None


def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


CurrentUser = Annotated[User, Depends(current_user)]
OptionalUser = Annotated[User | None, Depends(optional_user)]
AdminUser = Annotated[User, Depends(admin_user)]
