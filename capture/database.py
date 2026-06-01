"""
capture/database.py — SQLite database layer.
Creates the database schema and provides functions
to save and query honeypot events.
"""
import json
from datetime import datetime
from sqlalchemy import (create_engine, Column, Integer, String,
                        Float, Text, DateTime, Index)
from sqlalchemy.orm import declarative_base, sessionmaker

try:
    from config import DB_PATH
except ImportError:
    from pathlib import Path
    DB_PATH = Path("data/honeypot.db")

Base    = declarative_base()
engine  = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)


class AttackEvent(Base):
    """One row per honeypot event."""
    __tablename__ = "attack_events"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, nullable=False)
    service       = Column(String(16),  nullable=False)
    attacker_ip   = Column(String(45),  nullable=False)
    attacker_port = Column(Integer,     nullable=False)
    event_type    = Column(String(32),  nullable=False)
    details       = Column(Text,        default="{}")

    # ── Feature columns (filled by feature extractor) ──────────────────
    username      = Column(String(128), nullable=True)
    password      = Column(String(256), nullable=True)
    password_len  = Column(Integer,     nullable=True)
    http_method   = Column(String(10),  nullable=True)
    http_path     = Column(String(512), nullable=True)
    user_agent    = Column(String(512), nullable=True)
    payload       = Column(Text,        nullable=True)

    # ── ML label (filled after classification) ─────────────────────────
    attack_label  = Column(Integer,     nullable=True)
    attack_name   = Column(String(64),  nullable=True)

    __table_args__ = (
        Index("ix_ip",        "attacker_ip"),
        Index("ix_service",   "service"),
        Index("ix_event",     "event_type"),
        Index("ix_timestamp", "timestamp"),
    )

    def to_dict(self):
        return {
            "id"           : self.id,
            "timestamp"    : str(self.timestamp),
            "service"      : self.service,
            "attacker_ip"  : self.attacker_ip,
            "attacker_port": self.attacker_port,
            "event_type"   : self.event_type,
            "username"     : self.username,
            "password"     : self.password,
            "password_len" : self.password_len,
            "http_method"  : self.http_method,
            "http_path"    : self.http_path,
            "user_agent"   : self.user_agent,
            "attack_label" : self.attack_label,
            "attack_name"  : self.attack_name,
        }


def init_db():
    """Create all tables if they do not exist."""
    Base.metadata.create_all(engine)


def save_event(event: dict) -> AttackEvent:
    """
    Persist a honeypot event dict to the database.
    Returns the saved AttackEvent ORM object.
    """
    details = event.get("details", {})
    ts_raw  = event.get("timestamp")
    try:
        from datetime import timezone
        ts = datetime.fromisoformat(ts_raw).replace(tzinfo=None) if ts_raw else datetime.utcnow()
    except Exception:
        ts = datetime.utcnow()

    row = AttackEvent(
        timestamp     = ts,
        service       = event.get("service", ""),
        attacker_ip   = event.get("attacker_ip", ""),
        attacker_port = event.get("attacker_port", 0),
        event_type    = event.get("event_type", ""),
        details       = json.dumps(details),
        username      = details.get("username"),
        password      = details.get("password"),
        password_len  = len(details["password"]) if details.get("password") else None,
        http_method   = details.get("method"),
        http_path     = details.get("path"),
        user_agent    = details.get("user_agent"),
        payload       = details.get("body") or details.get("command"),
    )
    session = Session()
    try:
        session.add(row)
        session.commit()
        session.refresh(row)
        return row
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_recent_events(limit: int = 100) -> list:
    """Return the most recent N events as dicts."""
    session = Session()
    try:
        rows = (session.query(AttackEvent)
                .order_by(AttackEvent.id.desc())
                .limit(limit).all())
        return [r.to_dict() for r in rows]
    finally:
        session.close()


def get_stats() -> dict:
    """Return summary statistics for the dashboard."""
    session = Session()
    try:
        from sqlalchemy import func
        total   = session.query(func.count(AttackEvent.id)).scalar()
        by_svc  = dict(session.query(AttackEvent.service,
                       func.count(AttackEvent.id))
                       .group_by(AttackEvent.service).all())
        by_type = dict(session.query(AttackEvent.event_type,
                       func.count(AttackEvent.id))
                       .group_by(AttackEvent.event_type).all())
        by_ip   = dict(session.query(AttackEvent.attacker_ip,
                       func.count(AttackEvent.id))
                       .group_by(AttackEvent.attacker_ip)
                       .order_by(func.count(AttackEvent.id).desc())
                       .limit(10).all())
        return {"total": total, "by_service": by_svc,
                "by_event_type": by_type, "top_ips": by_ip}
    finally:
        session.close()


# Auto-initialise on import
init_db()