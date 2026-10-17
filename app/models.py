import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, Text, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from .database import Base


def gen_uuid():
    return str(uuid.uuid4())


class RawEvent(Base):
    __tablename__ = "raw_events"

    id = Column(String, primary_key=True, default=gen_uuid)
    source = Column(String, index=True)
    raw_payload = Column(JSON)
    event_type = Column(String, index=True)
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)

    incident = relationship("Incident", back_populates="events")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=gen_uuid)
    title = Column(String)
    description = Column(Text, nullable=True)
    severity_score = Column(Float, default=0.0)
    status = Column(String, default="open")
    mitre_techniques = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    analyst_notes = Column(Text, nullable=True)
    assigned_to = Column(String, nullable=True)
    webhook_sent = Column(Boolean, default=False)

    events = relationship("RawEvent", back_populates="incident")
    iocs = relationship("IOC", back_populates="incident")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, default=gen_uuid)
    ioc_type = Column(String)
    value = Column(String, index=True)
    known_bad = Column(String, default="unknown")
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="iocs")
