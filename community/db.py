"""Independent database. No Grocy connection or credential is accepted here."""
from contextlib import contextmanager
from sqlalchemy import (create_engine, MetaData, Table, Column, String, Text, Integer,
                        Boolean, Float, JSON, ForeignKey, UniqueConstraint, CheckConstraint,
                        Index, select, insert)

meta = MetaData()
schema_versions = Table("schema_versions", meta, Column("version", Integer, primary_key=True))
users = Table("users", meta,
    Column("id", String(32), primary_key=True), Column("email", String(320), unique=True),
    Column("name", String(80), nullable=False), Column("name_key", String(100), nullable=False, unique=True),
    Column("password", Text), Column("role", String(20), nullable=False, default="member"),
    Column("status", String(20), nullable=False, default="unverified"),
    Column("created", Float, nullable=False), Column("bio", Text, nullable=False, default=""),
    Column("totp", Text), Column("totp_pending", Text), Column("totp_counter", Integer, default=-1),
    Column("recovery", JSON, default=list), Column("preferences", JSON, default=dict),
    CheckConstraint("role IN ('member','moderator','admin')"),
    CheckConstraint("status IN ('invited','unverified','active','suspended','deleted')"))
sessions = Table("sessions", meta, Column("hash", String(64), primary_key=True),
    Column("user_id", String(32), ForeignKey("users.id")), Column("created", Float, nullable=False),
    Column("touched", Float, nullable=False), Column("expires", Float, nullable=False),
    Column("mfa", Boolean, nullable=False, default=False))
tokens = Table("tokens", meta, Column("hash", String(64), primary_key=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("kind", String(30), nullable=False), Column("payload", JSON, nullable=False),
    Column("expires", Float, nullable=False), Column("used", Boolean, nullable=False, default=False))
devices = Table("devices", meta, Column("hash", String(64), primary_key=True),
    Column("code_hash", String(64), nullable=False, unique=True),
    Column("instance", String(500), nullable=False), Column("scope", String(100), nullable=False),
    Column("expires", Float, nullable=False), Column("last_poll", Float, nullable=False, default=0),
    Column("user_id", String(32), ForeignKey("users.id")), Column("state", String(20), nullable=False))
grants = Table("grants", meta, Column("id", String(32), primary_key=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("access_hash", String(64), nullable=False, unique=True),
    Column("refresh_hash", String(64), nullable=False, unique=True), Column("scope", String(100), nullable=False),
    Column("instance", String(500), nullable=False), Column("expires", Float, nullable=False),
    Column("refresh_expires", Float, nullable=False), Column("created", Float, nullable=False))
entries = Table("entries", meta, Column("id", String(80), primary_key=True),
    Column("kind", String(20), nullable=False), Column("owner_id", String(32), ForeignKey("users.id")),
    Column("published", Integer), Column("latest", Integer, nullable=False, default=1),
    Column("created", Float, nullable=False), Column("withdrawn", Boolean, nullable=False, default=False),
    CheckConstraint("kind IN ('product','recipe','pack')"))
revisions = Table("revisions", meta, Column("id", String(80), ForeignKey("entries.id"), primary_key=True),
    Column("revision", Integer, primary_key=True), Column("author_id", String(32), ForeignKey("users.id")),
    Column("state", String(20), nullable=False), Column("content", JSON, nullable=False),
    Column("name", String(500), nullable=False), Column("language", String(10), nullable=False),
    Column("search", Text, nullable=False), Column("created", Float, nullable=False),
    Column("reviewed", Float), Column("reason", Text), Column("signature", Text), Column("digest", String(64)),
    CheckConstraint("state IN ('draft','pending','approved','published','rejected','withdrawn')"))
media = Table("media", meta, Column("id", String(64), primary_key=True),
    Column("owner_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("path", String(150), nullable=False), Column("size", Integer, nullable=False),
    Column("width", Integer, nullable=False), Column("height", Integer, nullable=False),
    Column("rights", JSON, nullable=False), Column("public", Boolean, nullable=False, default=False),
    Column("created", Float, nullable=False))
favorites = Table("favorites", meta, Column("user_id", String(32), ForeignKey("users.id"), primary_key=True),
    Column("entry_id", String(80), ForeignKey("entries.id"), primary_key=True), Column("created", Float, nullable=False))
subscriptions = Table("subscriptions", meta, Column("user_id", String(32), ForeignKey("users.id"), primary_key=True),
    Column("target", String(90), primary_key=True), Column("created", Float, nullable=False))
comments = Table("comments", meta, Column("id", String(32), primary_key=True),
    Column("entry_id", String(80), ForeignKey("entries.id"), nullable=False),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("text", Text, nullable=False), Column("state", String(20), nullable=False),
    Column("created", Float, nullable=False), Column("reason", Text))
ratings = Table("ratings", meta, Column("user_id", String(32), ForeignKey("users.id"), primary_key=True),
    Column("entry_id", String(80), ForeignKey("entries.id"), primary_key=True),
    Column("value", Integer, nullable=False), Column("created", Float, nullable=False),
    CheckConstraint("value BETWEEN 1 AND 5"))
reports = Table("reports", meta, Column("id", String(32), primary_key=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("entry_id", String(80), ForeignKey("entries.id"), nullable=False),
    Column("reason", Text, nullable=False), Column("state", String(20), nullable=False),
    Column("created", Float, nullable=False), Column("decision", Text))
notifications = Table("notifications", meta, Column("id", String(32), primary_key=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False), Column("kind", String(30), nullable=False),
    Column("message", Text, nullable=False), Column("entry_id", String(80)),
    Column("created", Float, nullable=False), Column("read", Boolean, nullable=False, default=False))
outbox = Table("outbox", meta, Column("id", String(64), primary_key=True),
    Column("payload", Text, nullable=False), Column("state", String(20), nullable=False),
    Column("attempts", Integer, nullable=False, default=0), Column("next_attempt", Float, nullable=False),
    Column("claimed", Float), Column("sent", Float), Column("error", String(100)),
    CheckConstraint("state IN ('pending','sending','sent','failed','uncertain')"))
audit = Table("audit", meta, Column("id", String(32), primary_key=True), Column("actor", String(32)),
    Column("action", String(60), nullable=False), Column("target", String(100)),
    Column("details", JSON, nullable=False), Column("created", Float, nullable=False))
limits = Table("limits", meta, Column("key", String(64), primary_key=True),
    Column("window", Integer, nullable=False), Column("count", Integer, nullable=False))
operations = Table("operations", meta, Column("actor", String(64), primary_key=True),
    Column("key", String(80), primary_key=True), Column("request_hash", String(64), nullable=False),
    Column("response", JSON, nullable=False), Column("status", Integer, nullable=False),
    Column("created", Float, nullable=False))
Index("revision_state", revisions.c.state, revisions.c.created)
Index("outbox_pending", outbox.c.state, outbox.c.next_attempt)

def engine(url):
    return create_engine(url, pool_pre_ping=True, future=True,
                         **({"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}))

def migrate(db):
    # Explicit operator operation; the web server does not perform DDL.
    meta.create_all(db)
    with db.begin() as conn:
        version = conn.execute(select(schema_versions.c.version)).scalar()
        if version is None: conn.execute(insert(schema_versions).values(version=1))
        elif version != 1: raise RuntimeError("Version de schéma incompatible")

def row(conn, table, condition):
    return conn.execute(select(table).where(condition)).mappings().first()

def uid():
    import uuid
    return uuid.uuid4().hex
