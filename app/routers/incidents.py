from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional

from .. import models, schemas
from ..database import get_db
from ..services import playbooks

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/", response_model=List[schemas.IncidentOut])
def list_incidents(
    status: Optional[str] = None,
    min_severity: float = 0,
    db: Session = Depends(get_db),
):
    q = db.query(models.Incident)
    if status:
        q = q.filter(models.Incident.status == status)
    q = q.filter(models.Incident.severity_score >= min_severity)
    return q.order_by(models.Incident.severity_score.desc()).all()


@router.get("/{incident_id}", response_model=schemas.IncidentOut)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}", response_model=schemas.IncidentOut)
def update_incident(incident_id: str, update: schemas.IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if update.status:
        incident.status = update.status
    if update.analyst_notes is not None:
        incident.analyst_notes = update.analyst_notes

    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}/playbook", response_model=dict)
def get_incident_playbook(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_id": incident.id, "playbook": playbooks.get_playbook(incident)}


@router.get("/{incident_id}/report", response_model=dict)
def get_incident_report(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(models.Incident).get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    lines = [
        f"# Incident Report: {incident.title}",
        f"**Status:** {incident.status}  |  **Severity:** {incident.severity_score}/100",
        f"**MITRE Techniques:** {', '.join(incident.mitre_techniques) or 'none mapped'}",
        "",
        "## Timeline",
    ]
    for e in sorted(incident.events, key=lambda ev: ev.timestamp):
        lines.append(f"- `{e.timestamp}` — {e.event_type} from {e.src_ip or 'n/a'} (source: {e.source})")

    lines.append("\n## Indicators of Compromise")
    for ioc in incident.iocs:
        lines.append(f"- {ioc.ioc_type}: `{ioc.value}` (known bad: {ioc.known_bad})")

    if incident.analyst_notes:
        lines.append(f"\n## Analyst Notes\n{incident.analyst_notes}")

    return {"markdown": "\n".join(lines)}
