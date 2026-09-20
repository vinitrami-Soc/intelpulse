"""Runtime configuration for the IntelPulse triage backend.

Every external dependency (Redis, Postgres, each threat-intel API, the MaxMind
database) is optional: a missing key disables that provider instead of breaking
the request. That keeps `docker compose up` usable for a reviewer who has no
API keys at all.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BACKEND_ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(BACKEND_ROOT.parent / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- service ---------------------------------------------------------
    app_name: str = "IntelPulse"
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "*"
    data_dir: Path = DEFAULT_DATA_DIR

    # --- storage ---------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./data/intelpulse.db"
    redis_url: str | None = None
    cache_ttl_seconds: int = 86_400          # 24h — matches the free-tier quotas
    cache_negative_ttl_seconds: int = 3_600  # provider errors are retried sooner

    # --- provider credentials (all optional) -----------------------------
    abuseipdb_api_key: str | None = None
    otx_api_key: str | None = None
    greynoise_api_key: str | None = None
    abusech_auth_key: str | None = None   # shared by ThreatFox + URLhaus
    virustotal_api_key: str | None = None

    # --- provider behaviour ----------------------------------------------
    provider_timeout_seconds: float = 8.0
    max_iocs_per_request: int = 100
    max_upload_bytes: int = 5 * 1024 * 1024
    # RFC 5737 / RFC 3849 documentation addresses are non-routable and therefore
    # dropped during extraction. The bundled offline demo dataset uses exactly
    # those ranges (that is what they are for), so the demo path opts back in.
    allow_documentation_ranges: bool = False
    abuseipdb_max_age_days: int = 90

    # --- offline datasets --------------------------------------------------
    geoip_city_db: Path = DEFAULT_DATA_DIR / "GeoLite2-City.mmdb"
    geoip_asn_db: Path = DEFAULT_DATA_DIR / "GeoLite2-ASN.mmdb"

    # --- composite scoring weights ---------------------------------------
    # Weights are relative: the engine normalises by the weight of the signals
    # that actually returned data, so one dead API cannot deflate a verdict.
    weight_abuseipdb: float = Field(default=1.0, ge=0)
    weight_otx: float = Field(default=0.9, ge=0)
    weight_threatfox: float = Field(default=1.2, ge=0)
    weight_urlhaus: float = Field(default=1.1, ge=0)
    weight_local_blocklist: float = Field(default=1.0, ge=0)
    weight_greynoise: float = Field(default=0.6, ge=0)
    weight_geo_asn: float = Field(default=0.25, ge=0)

    # GreyNoise "benign" means internet background noise (Shodan, Censys,
    # research scanners). It suppresses but never zeroes a verdict.
    greynoise_benign_multiplier: float = 0.45
    score_high_threshold: int = 70
    score_medium_threshold: int = 40
    score_low_threshold: int = 15

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def provider_weights(self) -> dict[str, float]:
        return {
            "abuseipdb": self.weight_abuseipdb,
            "otx": self.weight_otx,
            "threatfox": self.weight_threatfox,
            "urlhaus": self.weight_urlhaus,
            "local_blocklist": self.weight_local_blocklist,
            "greynoise": self.weight_greynoise,
            "geoip": self.weight_geo_asn,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
