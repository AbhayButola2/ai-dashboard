"""
db/models.py
------------
SQLAlchemy ORM models. Schema matches the normalized log format from log_parser.py.
"""
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from sqlalchemy.sql import func
from db.database import Base


class LogEntry(Base):
    __tablename__ = "logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    log_id      = Column(String(64), unique=True, index=True)   # feodo-0, blde-1, etc.
    timestamp   = Column(String(64), index=True)
    source_ip   = Column(String(64), index=True)
    destination_ip = Column(String(64), nullable=True)
    threat_type = Column(String(128))
    severity    = Column(String(32))
    source      = Column(String(64))
    ioc_type    = Column(String(64), nullable=True)
    malware_alias = Column(String(128), nullable=True)
    tags        = Column(Text, nullable=True)
    confidence  = Column(Float, nullable=True)
    dst_port    = Column(Integer, nullable=True)
    raw_log     = Column(Text)
    # Embedding stored as JSON string
    embedding   = Column(Text, nullable=True)
    # GNN anomaly score
    anomaly_score = Column(Float, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())

    # Note: index=True on timestamp/source_ip/log_id columns above
    # already creates the necessary indexes; no need for explicit __table_args__.

    def to_dict(self) -> dict:
        return {
            "id":             self.log_id,
            "timestamp":      self.timestamp,
            "ioc":            self.source_ip,
            "ioc_type":       self.ioc_type,
            "source":         self.source,
            "threat_type":    self.threat_type,
            "severity":       self.severity,
            "malware_alias":  self.malware_alias,
            "tags":           self.tags,
            "confidence":     self.confidence,
            "dst_port":       self.dst_port,
            "dst_ip":         self.destination_ip,
            "raw_line":       self.raw_log,
            "anomaly_score":  self.anomaly_score,
        }
