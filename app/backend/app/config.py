"""Application configuration. Zero external services; env-driven, local-first.

All defaults are safe for an offline local lab. See ADR-006 (secrets).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # app/backend


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    env_name: str = "LOCAL"
    port: int = 8080
    data_dir: Path = field(default_factory=lambda: BASE_DIR / "data")
    secret_key: str = "dev-only-change-me-in-staging"
    token_ttl_hours: int = 12
    dev_origin: str | None = None
    rules_dir: Path = field(default_factory=lambda: BASE_DIR / "rules")
    scenarios_dir: Path = field(default_factory=lambda: BASE_DIR / "scenarios")
    frontend_dist: Path = field(default_factory=lambda: BASE_DIR.parent / "frontend" / "dist")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cybersec.db"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.evidence_dir, self.reports_dir, self.backups_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    s = Settings()
    s.env_name = os.environ.get("ENV_NAME", s.env_name).strip() or "LOCAL"
    if s.env_name not in {"LOCAL", "LAB", "STAGING", "PROD"}:
        s.env_name = "LOCAL"
    s.port = int(os.environ.get("PORT", s.port))
    data = os.environ.get("DATA_DIR")
    if data:
        s.data_dir = Path(data) if Path(data).is_absolute() else BASE_DIR / data
    s.secret_key = os.environ.get("SECRET_KEY", s.secret_key)
    s.token_ttl_hours = int(os.environ.get("TOKEN_TTL_HOURS", s.token_ttl_hours))
    s.dev_origin = os.environ.get("DEV_ORIGIN") or None
    s.ensure_dirs()
    if s.env_name in {"STAGING", "PROD"} and s.secret_key == "dev-only-change-me-in-staging":
        raise RuntimeError(
            "SECRET_KEY must be set to a strong unique value when ENV_NAME is STAGING or PROD "
            "(see ADR-006). Refusing to boot with the dev default."
        )
    return s


settings = load_settings()
