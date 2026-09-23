"""Request/response contracts for the public API."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .text import clean_label

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

    @model_validator(mode="after")
    def _something_to_triage(self) -> TriageRequest:
        """In the schema, not only in the route: an empty request is a 422 the
        OpenAPI contract describes, rather than one it contradicts."""
        if not (self.text and self.text.strip()) and not any((i or "").strip() for i in (self.indicators or [])):
            raise ValueError("provide either `text` or `indicators`")
        return self

    @field_validator("title")
    @classmethod
    def _one_line_title(cls, value: str) -> str:
        """A title is a label. With a newline in it, it could write its own
        section into the ticket; with a bidi override, read as something else."""
        return clean_label(value, 200) or "Ad-hoc triage"

    @field_validator("analyst")
    @classmethod
    def _one_line_analyst(cls, value: str | None) -> str | None:
        return clean_label(value, 120) or None if value is not None else None


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
    # What changed since each indicator was last triaged. Empty when the caller
    # did not ask for persistence: with nothing written, there is no history to
    # compare against and an empty list is the honest answer.
    diffs: list[dict[str, Any]] = []


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
    value: str = Field(..., min_length=1, max_length=2048)
    # Ignored on the way in: the server classifies the value itself.
    ioc_type: str = Field(default="ip", max_length=16)
    list_type: Literal["allow", "block"] = "allow"
    reason: str = Field(default="", max_length=500)
    # A label, never an identity: the audit log records who the server verified.
    created_by: str | None = Field(default=None, max_length=120)


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
    # Which trackers this deployment can raise a ticket in. Empty is the normal
    # answer; the dashboard offers a button only for what is listed here.
    ticket_sinks: list[str] = []
