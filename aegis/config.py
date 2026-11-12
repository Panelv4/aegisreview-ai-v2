"""Application settings (pydantic-settings, env/.env driven)."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    PROJECT_NAME: str = "AegisReview"
    API_PREFIX: str = "/api"
    VERSION: str = "2.0.0"

    DATABASE_URL: str = "sqlite:///./aegis.db"
    SECRET_KEY: str = ""          # generated per-process if unset (dev only)
    ACCESS_TOKEN_MINUTES: int = 720
    REFRESH_TOKEN_DAYS: int = 14

    CORS_ORIGINS: str = "*"

    # limits
    MAX_UPLOAD_MB: int = 5
    MAX_REPO_MB: int = 25
    ALLOW_REGISTRATION: bool = True

    # demo data on first boot
    SEED_DEMO: bool = True

    @property
    def secret_key(self) -> str:
        """Signing key.

        If SECRET_KEY is unset we generate one and persist it beside the
        database (mode 0600) rather than minting a fresh key per process. A
        per-process key silently invalidates every session on restart, which
        looks like an auth bug to users and trains them to re-login blindly.
        In production set SECRET_KEY explicitly.
        """
        if not self.SECRET_KEY:
            key_file = self._key_file()
            if key_file.exists():
                self.SECRET_KEY = key_file.read_text(encoding="utf-8").strip()
            else:
                self.SECRET_KEY = secrets.token_urlsafe(48)
                try:
                    key_file.parent.mkdir(parents=True, exist_ok=True)
                    key_file.write_text(self.SECRET_KEY, encoding="utf-8")
                    os.chmod(key_file, 0o600)
                except OSError:
                    pass  # read-only FS: fall back to an ephemeral key
        return self.SECRET_KEY

    def _key_file(self) -> Path:
        if self.DATABASE_URL.startswith("sqlite"):
            # keep the key next to the sqlite file so the two move together
            db_path = Path(self.DATABASE_URL.split("///", 1)[-1])
            return db_path.parent / ".aegis_secret"
        return Path(".aegis_secret")

    @property
    def cors_origins(self) -> list[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
