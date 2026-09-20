"""SQLAlchemy models: investigation history, analyst lists, offline datasets."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Case(Base):
    """One triage run — the unit an analyst attaches to a ticket."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), default="Untitled triage")
    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual|paste|upload|api
    analyst: Mapped[str | None] = mapped_column(String(120), nullable=True)
    raw_input: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict: Mapped[str] = mapped_column(String(20), default="informational")
    max_score: Mapped[int] = mapped_column(Integer, default=0)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    indicators: Mapped[list[IndicatorResult]] = relationship(
        back_populates="case", cascade="all, delete-orphan", lazy="selectin"
    )


class IndicatorResult(Base):
    """Per-indicator verdict plus the full provider payload that produced it."""

    __tablename__ = "indicator_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(20), default="informational")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    malware_families: Mapped[list] = mapped_column(JSON, default=list)
    attack_ids: Mapped[list] = mapped_column(JSON, default=list)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="indicators")


class ListEntry(Base):
    """Analyst-maintained allowlist / blocklist — overrides vendor opinion."""

    __tablename__ = "list_entries"
    __table_args__ = (UniqueConstraint("value", "list_type", name="uq_list_value_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16), default="ip")
    list_type: Mapped[str] = mapped_column(String(16), default="allow")  # allow|block
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FeedEntry(Base):
    """Offline feed rows (Feodo Tracker, FireHOL, ThreatFox daily dump)."""

    __tablename__ = "feed_entries"
    __table_args__ = (
        UniqueConstraint("value", "feed", name="uq_feed_value"),
        Index("ix_feed_entries_value_feed", "value", "feed"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16), default="ip")
    feed: Mapped[str] = mapped_column(String(64))
    malware_family: Mapped[str | None] = mapped_column(String(120), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=75)
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FeedRun(Base):
    """Bookkeeping for offline dataset refreshes (shown on the UI status bar)."""

    __tablename__ = "feed_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feed: Mapped[str] = mapped_column(String(64), index=True)
    rows: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CveRecord(Base):
    """Offline slice of the NVD CVE feed used for vulnerability correlation."""

    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    published: Mapped[str | None] = mapped_column(String(40), nullable=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    references: Mapped[list] = mapped_column(JSON, default=list)


class AuditLog(Base):
    """Append-only trail: who triaged what, and what the platform decided."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(120), default="anonymous")
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
