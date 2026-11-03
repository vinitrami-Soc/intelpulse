"""SQLAlchemy models: workspaces and accounts, investigation history, analyst lists,
offline datasets.

Every row a workspace owns carries `workspace_id`; the offline feeds are shared
by every workspace. The schema itself is owned by the migrations in
`app/migrations`, which a test keeps equal to these models."""
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
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


# The organization a 1.x database's rows moved to (migration 0002).
DEFAULT_WORKSPACE_ID = 1
DEFAULT_WORKSPACE_NAME = "Default organization"
# Settings and audit records of the server itself, not of any workspace.
SERVER = 0


class Workspace(Base):
    """An organization or one person: everything they triage is theirs alone."""

    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(20), default="organization")  # organization|individual
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    """A member of exactly one workspace, as its admin or an analyst."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    email_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # admin|analyst
    owner: Mapped[bool] = mapped_column(Boolean, default=False)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginSession(Base):
    """A signed-in browser. The id is the SHA-256 of the cookie, never the cookie."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiToken(Base):
    """A workspace's token for scripts and integrations; only its SHA-256 is kept."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(64))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scope: Mapped[str] = mapped_column(String(16))  # read|triage|ingest
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Setting(Base):
    """One setting of a workspace, or of the server (workspace SERVER). A secret is
    kept only sealed, in `sealed`; anything else is plain JSON in `value`."""

    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("workspace_id", "key", name="uq_setting_workspace_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(Integer, index=True)
    key: Mapped[str] = mapped_column(String(64))
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON, nullable=True)
    sealed: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Case(Base):
    """One triage run — the unit an analyst attaches to a ticket."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(200), default="Untitled triage")
    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual|paste|upload|api
    analyst: Mapped[str | None] = mapped_column(String(120), nullable=True)
    raw_input: Mapped[str | None] = mapped_column(Text, nullable=True)
    verdict: Mapped[str] = mapped_column(String(20), default="informational")
    max_score: Mapped[int] = mapped_column(Integer, default=0)
    indicator_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # the workflow (spec 8.3): new -> in_progress -> closed, with a reason; reopening clears it
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    assignee_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL", name="fk_cases_assignee_id"), nullable=True, index=True
    )
    closed_reason: Mapped[str | None] = mapped_column(String(20), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    indicators: Mapped[list[IndicatorResult]] = relationship(
        back_populates="case", cascade="all, delete-orphan", lazy="selectin"
    )


class PushedAlert(Base):
    """An alert a SIEM pushed to /api/alerts, kept beside the case its triage produced.

    A table of its own rather than columns on `cases`, from before the schema had
    migrations; it stays one, since a case made by hand has no alert.
    """

    __tablename__ = "pushed_alerts"
    # The sender's own id makes a retried push the same alert, not a second case,
    # within one workspace: two workspaces may receive alerts with the same ids.
    __table_args__ = (
        UniqueConstraint("workspace_id", "source", "alert_id", name="uq_pushed_alert_source_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(40))
    alert_id: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IndicatorResult(Base):
    """Per-indicator verdict plus the full provider payload that produced it."""

    __tablename__ = "indicator_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
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
    __table_args__ = (UniqueConstraint("workspace_id", "value", "list_type", name="uq_list_value_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
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
    """Append-only trail: who triaged what, and what the platform decided.

    A hash chain: each record's `hash` covers its own fields and the hash of the
    record before it, and `AuditHead` keeps the newest hash and the count, so an
    edited, removed, reordered or cut-off record is found by `audit.verify()`.
    Written only through `app.platform.audit.record()`. `workspace_id` has no
    foreign key on purpose: a workspace's trail outlives the workspace.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(120), default="anonymous")
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class CaseTicket(Base):
    """An issue raised for a case in Jira or ServiceNow: the SOC tickets view lists these."""

    __tablename__ = "case_tickets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    sink: Mapped[str] = mapped_column(String(20))
    key: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditHead(Base):
    """One row: the newest audit record's hash and how many records there are."""

    __tablename__ = "audit_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(Integer, default=0)


class Invite(Base):
    """A one-use link into a workspace, for a role. Only the SHA-256 of its token is kept."""

    __tablename__ = "invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL", name="fk_invites_created_by"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL", name="fk_invites_used_by"), nullable=True
    )


class EmailToken(Base):
    """A link sent by email: to confirm an address, or to reset a password. Only its SHA-256 is kept."""

    __tablename__ = "email_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))  # confirm | reset
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), default="")  # the address a confirmation confirms
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
