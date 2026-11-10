"""Datenmodell (SQLite über SQLAlchemy)."""
import datetime as dt
import json
import os

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from . import security as sec

DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)
engine = create_engine(f"sqlite:///{DATA_DIR}/gateway.db", connect_args={"check_same_thread": False, "timeout": 30})


@event.listens_for(engine, "connect")
def _sqlite_pragmas(conn, _):
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


SessionLocal = sessionmaker(engine, expire_on_commit=False)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))


class Tenant(Base):
    """Ein Kunde mit eigenem DIVERA-Zugang."""
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    accesskey_enc: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    test_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    sources: Mapped[list["Source"]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    rules: Mapped[list["Rule"]] = relationship(back_populates="tenant", cascade="all, delete-orphan",
                                               order_by="Rule.position, Rule.id")


class Source(Base):
    """Datenquelle: m365, imap oder webhook."""
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[str] = mapped_column(String(20))
    config_enc: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[str] = mapped_column(Text, default="{}")
    webhook_token: Mapped[str | None] = mapped_column(String(80), unique=True, nullable=True)
    poll_interval: Mapped[int] = mapped_column(Integer, default=30)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_poll: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    tenant: Mapped[Tenant] = relationship(back_populates="sources")

    @property
    def config(self) -> dict:
        return json.loads(sec.decrypt(self.config_enc) or "{}")

    @config.setter
    def config(self, value: dict):
        self.config_enc = sec.encrypt(json.dumps(value))


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True)
    name: Mapped[str] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    position: Mapped[int] = mapped_column(Integer, default=10)
    match_from: Mapped[str] = mapped_column(String(200), default="")
    match_subject: Mapped[str] = mapped_column(String(200), default="")
    match_body: Mapped[str] = mapped_column(String(200), default="")
    extract_regex: Mapped[str] = mapped_column(Text, default="")
    require_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    kind: Mapped[str] = mapped_column(String(10), default="alarm")  # alarm | news
    title_tpl: Mapped[str] = mapped_column(Text, default="{subject}")
    text_tpl: Mapped[str] = mapped_column(Text, default="{body}")
    address_tpl: Mapped[str] = mapped_column(Text, default="")
    ric: Mapped[str] = mapped_column(String(300), default="")
    priority: Mapped[bool] = mapped_column(Boolean, default=False)
    extra_params: Mapped[str] = mapped_column(Text, default="")
    stop: Mapped[bool] = mapped_column(Boolean, default=True)
    tenant: Mapped[Tenant] = relationship(back_populates="rules")
    source: Mapped[Source | None] = relationship()


class Log(Base):
    __tablename__ = "logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    tenant_name: Mapped[str] = mapped_column(String(120), default="")
    source_name: Mapped[str] = mapped_column(String(120), default="")
    rule_name: Mapped[str] = mapped_column(String(120), default="")
    sender: Mapped[str] = mapped_column(String(200), default="")
    subject: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(20), default="")  # gesendet | test | fehler | ignoriert | veraltet
    detail: Mapped[str] = mapped_column(Text, default="")


class Processed(Base):
    """Bereits verarbeitete Nachrichten, damit nichts doppelt alarmiert wird."""
    __tablename__ = "processed"
    __table_args__ = (UniqueConstraint("source_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(400))
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


def init_db():
    Base.metadata.create_all(engine)
