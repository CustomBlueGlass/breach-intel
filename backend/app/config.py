"""
Central configuration. All secrets/keys come from environment variables —
never hardcode API keys for HIBP / DeHashed / Intelx / LeakIX.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://breach:breach@localhost:5432/breach_intel"
    redis_url: str | None = None  # leave unset for the free Supabase deployment (no Redis)

    # collector cadence
    collector_interval_minutes: int = 360  # every 6 hours, per spec

    # correlation thresholds
    auto_merge_confidence_threshold: float = 0.90
    queue_confidence_threshold: float = 0.55  # below this, discard as unrelated noise

    # api keys (set in .env / deployment secrets — all optional, collectors
    # disable themselves gracefully if their key is absent)
    leakix_api_key: str | None = None
    hibp_api_key: str | None = None
    dehashed_api_key: str | None = None
    intelx_api_key: str | None = None

    # politeness / scraping etiquette for the html fallback collector
    scraper_user_agent: str = "BreachIntelBot/1.0 (+contact: ops@yourcompany.example)"
    scraper_min_delay_seconds: float = 2.0
    scraper_respect_robots_txt: bool = True

    pagination_max_page_size: int = 50
    pagination_default_page_size: int = 25

    class Config:
        env_file = ".env"


settings = Settings()
