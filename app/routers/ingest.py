import json
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..services import correlation, scoring, mitre_mapping, ioc_extraction

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("/event", response_model=schemas.IncidentOut)
def ingest_event(event_in: schemas.RawEventIn, db: Session = Depends(get_db)):
    """
    Single entry point for feeding ABEKE logs/alerts. Pipeline:
    1. store the raw event
    2. correlate it into an incident (new or existing)
    3. extract IOCs from the payload
    4. re-map MITRE techniques for the incident
    5. recompute severity score
    """
    event = models.RawEvent(
        source=event_in.source,
        event_type=event_in.event_type,
        raw_payload=event_in.raw_payload,
        src_ip=event_in.src_ip,
        dst_ip=event_in.dst_ip,
        timestamp=event_in.timestamp or datetime.utcnow(),
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    incident = correlation.correlate_event(db, event)

    blob = json.dumps(event_in.raw_payload)
    for ioc in ioc_extraction.extract_iocs(blob):
        db.add(models.IOC(incident_id=incident.id, **ioc))
    db.commit()

    db.refresh(incident)
    incident.mitre_techniques = mitre_mapping.map_techniques(
        [e.event_type for e in incident.events]
    )
    scoring.score_incident(db, incident)
    db.commit()
    db.refresh(incident)

    return incident
