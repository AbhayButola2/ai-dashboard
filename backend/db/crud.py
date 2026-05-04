"""
db/crud.py
----------
CRUD helpers for LogEntry. Used by main.py and ingestion_worker.py.
"""
import json
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from db.models import LogEntry


def upsert_log(db: Session, record: dict) -> LogEntry:
    """Insert or update a log record by log_id."""
    log_id = record.get("id", "")
    existing = db.query(LogEntry).filter(LogEntry.log_id == log_id).first()

    values = dict(
        log_id        = log_id,
        timestamp     = str(record.get("timestamp", "")),
        source_ip     = str(record.get("ioc", "")),
        destination_ip = str(record.get("dst_ip", "")),
        threat_type   = str(record.get("threat_type", "")),
        severity      = str(record.get("severity", "Unknown")),
        source        = str(record.get("source", "")),
        ioc_type      = str(record.get("ioc_type", "")),
        malware_alias = str(record.get("malware_alias", "")),
        tags          = str(record.get("tags", "")),
        confidence    = float(record.get("confidence", 0) or 0),
        dst_port      = int(record.get("dst_port") or 0),
        raw_log       = str(record.get("raw_line", "")),
    )

    if existing:
        for k, v in values.items():
            setattr(existing, k, v)
        db.commit()
        db.refresh(existing)
        return existing
    else:
        entry = LogEntry(**values)
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry


def bulk_upsert(db: Session, records: list) -> int:
    """Upsert many records; returns count inserted/updated."""
    count = 0
    for rec in records:
        upsert_log(db, rec)
        count += 1
    return count


def get_all_logs(db: Session, limit: int = 1000) -> List[LogEntry]:
    return db.query(LogEntry).order_by(desc(LogEntry.id)).limit(limit).all()


def get_log_by_id(db: Session, log_id: str) -> Optional[LogEntry]:
    return db.query(LogEntry).filter(LogEntry.log_id == log_id).first()


def get_stats(db: Session) -> dict:
    """Aggregate stats — replaces the JSON-based stats."""
    total = db.query(func.count(LogEntry.id)).scalar() or 0
    severities = {}
    for row in db.query(LogEntry.severity, func.count(LogEntry.id)).group_by(LogEntry.severity).all():
        severities[row[0]] = row[1]
    sources = {}
    for row in db.query(LogEntry.source, func.count(LogEntry.id)).group_by(LogEntry.source).all():
        sources[row[0]] = row[1]
    threat_types = {}
    for row in db.query(LogEntry.threat_type, func.count(LogEntry.id)).group_by(LogEntry.threat_type).all():
        threat_types[row[0]] = row[1]
    return {
        "total_threats": total,
        "severities":    severities,
        "sources":       sources,
        "threat_types":  threat_types,
    }


def update_embedding(db: Session, log_id: str, embedding: list):
    """Store a float list as JSON in the embedding column."""
    entry = get_log_by_id(db, log_id)
    if entry:
        entry.embedding = json.dumps(embedding)
        db.commit()


def get_logs_with_embeddings(db: Session) -> List[LogEntry]:
    return db.query(LogEntry).filter(LogEntry.embedding.isnot(None)).all()


def update_anomaly_score(db: Session, log_id: str, score: float):
    entry = get_log_by_id(db, log_id)
    if entry:
        entry.anomaly_score = score
        db.commit()
