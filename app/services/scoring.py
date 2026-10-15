from sqlalchemy.orm import Session
from .. import models

# Base weight per event_type — extend this as you add more detection sources
EVENT_TYPE_WEIGHTS = {
    "login_failed": 5,
    "login_success_after_failures": 25,
    "port_scan": 15,
    "malware_detected": 40,
    "privilege_escalation": 35,
    "data_exfil_suspected": 50,
    "known_bad_ioc_hit": 30,
}
DEFAULT_WEIGHT = 8


def score_incident(db: Session, incident: models.Incident) -> float:
    """
    Recompute an incident's severity score (0-100) from its event volume,
    event types, and whether any attached IOC is known-bad.
    """
    score = 0.0
    for event in incident.events:
        score += EVENT_TYPE_WEIGHTS.get(event.event_type, DEFAULT_WEIGHT)

    # repeated events from the same source escalate faster than isolated ones
    if len(incident.events) > 5:
        score += 10

    if any(ioc.known_bad == "yes" for ioc in incident.iocs):
        score += 20

    score = min(score, 100.0)

    incident.severity_score = score
    db.commit()
    return score
