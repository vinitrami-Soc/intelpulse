"""Request/response contracts for the public API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

MAX_INPUT_CHARS = 200_000


class ExtractRequest(BaseModel):
    text: str = Field(
        ...,
        max_length=MAX_INPUT_CHARS,
        description="Raw paste: IOC list, syslog, JSON alert export",
    )
    limit: int | None = Field(default=None, ge=1, le=500)


class ExtractedIndicator(BaseModel):
    value: str
    type: str
    original: str
    context: str = ""


class ExtractResponse(BaseModel):
    count: int
    counts_by_type: dict[str, int]
    indicators: list[ExtractedIndicator]


class TriageRequest(BaseModel):
    """Accepts either a raw blob (`text`) or an explicit indicator list."""

    text: str | None = Field(default=None, max_length=MAX_INPUT_CHARS)
    indicators: list[str] | None = Field(default=None, max_length=500)
    title: str = Field(default="Ad-hoc triage", max_length=200)
    analyst: str | None = Field(default=None, max_length=120)
    use_cache: bool = True
    persist: bool = True
    limit: int | None = Field(default=None, ge=1, le=200)


class TriageResponse(BaseModel):
    case_id: str
    title: str
    verdict: str
    score: int
    summary: str
    duration_ms: int
    cache_hits: int
    indicator_count: int
    indicators: list[dict[str, Any]]
    graph: dict[str, Any]
    persisted: bool = False


class CaseSummary(BaseModel):
    id: str
    title: str
    verdict: str
    max_score: int
    indicator_count: int
    source: str
    analyst: str | None = None
    duration_ms: int
    created_at: str


class ListEntryIn(BaseModel):
    value: str
    ioc_type: str = "ip"
    list_type: Literal["allow", "block"] = "allow"
    reason: str = ""
    created_by: str | None = None


class ListEntryOut(ListEntryIn):
    id: int
    created_at: str


class ProviderStatus(BaseModel):
    name: str
    label: str
    supported_types: list[str]
    requires_key: bool
    configured: bool


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str
    database: str
    cache: dict[str, Any]
    providers: list[ProviderStatus]
    offline_datasets: dict[str, Any]
