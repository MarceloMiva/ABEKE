import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from .database import Base


def gen_uuid():
    return str(uuid.uuid4())


class RawEvent(Base):
    """A single ingested log/alert line, before correlation."""
    __tablename__ = "raw_events"

    id = Column(String, primary_key=True, default=gen_uuid)
    source = Column(String, index=True)          # e.g. "firewall", "edr", "auth-log"
    raw_payload = Column(JSON)                    # original event as received
    event_type = Column(String, index=True)       # e.g. "login_failed", "port_scan"
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)

    incident = relationship("Incident", back_populates="events")


class Incident(Base):
    """A correlated group of events, scored and tracked as one case."""
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=gen_uuid)
    title = Column(String)
    description = Column(Text, nullable=True)
    severity_score = Column(Float, default=0.0)     # 0-100, from scoring service
    status = Column(String, default="open")          # open | investigating | resolved | false_positive
    mitre_techniques = Column(JSON, default=list)     # e.g. ["T1110", "T1078"]
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    analyst_notes = Column(Text, nullable=True)

    events = relationship("RawEvent", back_populates="incident")
    iocs = relationship("IOC", back_populates="incident")


class IOC(Base):
    """Indicator of Compromise extracted from events."""
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, default=gen_uuid)
    ioc_type = Column(String)      # ip | domain | hash | email
    value = Column(String, index=True)
    known_bad = Column(String, default="unknown")  # "yes" | "no" | "unknown"
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="iocs")
