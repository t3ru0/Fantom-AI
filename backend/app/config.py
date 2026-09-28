"""Configuration. Everything comes from the environment; nothing is hardcoded.

Read once at import, validated by pydantic. If a required secret is missing the
app still starts — it reports the capability as unavailable on /health rather
than crashing, so a half-configured dev machine is still useful.
"""
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ---- app ---------------------------------------------------------------
    app_name: str = "fantom"
    env: Literal["dev", "test", "prod"] = "dev"
    debug: bool = False
    api_prefix: str = "/api"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # ---- database ----------------------------------------------------------
    # MySQL (XAMPP). Schema uses generic SQLAlchemy Uuid/JSON types so it
    # works on both MySQL and Postgres without dialect-specific columns.
    database_url: str = "mysql+pymysql://root:@localhost:3306/fantom"
    db_pool_size: int = 5
    db_echo: bool = False
    db_connect_timeout: int = 3   # seconds; keeps /health bounded

    # ---- redis / queue (Part 4) -------------------------------------------
    redis_url: str = "redis://localhost:6379/0"

    # ---- auth ---------------------------------------------------------------
    jwt_secret: str = "dev-insecure-secret-change-me-32bytes-minimum"     # override in .env for real deployments
    jwt_access_ttl_min: int = 15
    jwt_refresh_ttl_days: int = 30
    frontend_url: str = "http://localhost:5173"

    # ---- outbound email (password reset) ------------------------------------
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "no-reply@fantom.ai"

    # ---- github app (Part 1) ----------------------------------------------
    github_app_id: str | None = None
    github_webhook_secret: str | None = None
    github_private_key: str | None = None          # PEM, newlines as \n
    github_client_id: str | None = None
    github_client_secret: str | None = None

    # ---- github connector (Connector V1) -----------------------------------
    github_redirect_uri: str = "http://localhost:8000/connectors/github/callback"
    github_encryption_key: str | None = None        # base64, decodes to exactly 32 bytes
    github_encryption_key_previous: str | None = None   # set only mid-rotation; same format
    github_api_base: str = "https://api.github.com"
    github_sync_page_size: int = 100
    github_clone_timeout: int = 120
    connector_sync_interval_hours: float = 6.0

    # ---- llm (Part 5) ------------------------------------------------------
    openrouter_api_key: str | None = None
    model_cheap: str = "qwen/qwen3.7-flash"
    model_reason: str = "deepseek/deepseek-v4-pro-0813"
    model_narrate: str = "google/gemini-3.8-flash"

    # ---- scanning limits (Part 2) -----------------------------------------
    max_repo_mb: int = 500
    scanner_timeout_s: int = 300
    workspace_dir: str = "./.workspaces"

    # ---- risk model defaults (Part 7) -------------------------------------
    # These are the ONLY money defaults in the system. Every other financial
    # figure requires the user to supply business context first.
    default_eng_rate_hour: float = 120.0
    oh_review_multiple: float = 0.8
    oh_ship_hours: float = 8.0
    oh_coord_hours: float = 6.0
    sprint_hours: float = 160.0

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def github_ready(self) -> bool:
        return bool(self.github_app_id and self.github_webhook_secret and self.github_private_key)

    @property
    def github_oauth_ready(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret and self.github_encryption_key)

    @property
    def llm_ready(self) -> bool:
        return bool(self.openrouter_api_key)

    @property
    def smtp_ready(self) -> bool:
        return bool(self.smtp_host and self.smtp_user)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
