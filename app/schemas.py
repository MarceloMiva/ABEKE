from datetime import datetime
from typing import Optional, Any, List
from pydantic import BaseModel


class RawEventIn(BaseModel):
    source: str
    event_type: str
    raw_payload: dict[str, Any]
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    timestamp: Optional[datetime] = None


class RawEventOut(RawEventIn):
    id: str
    incident_id: Optional[str] = None

    class Config:
        from_attributes = True


class IOCOut(BaseModel):
    id: str
    ioc_type: str
    value: str
    known_bad: str

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity_score: float
    status: str
    mitre_techniques: List[str] = []
    created_at: datetime
    iocs: List[IOCOut] = []
    assigned_to: Optional[str] = None

    class Config:
        from_attributes = True


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    assigned_to: Optional[str] = None
