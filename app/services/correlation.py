from datetime import timedelta
from sqlalchemy.orm import Session
from .. import models

# Events sharing src_ip + event_type within this window get grouped into one incident.
# Tune this per environment — tighter for noisy auth logs, looser for slow recon.
CORRELATION_WINDOW = timedelta(minutes=15)


def correlate_event(db: Session, event: models.RawEvent) -> models.Incident:
    """
    Try to attach a new raw event to an existing open incident; otherwise
    create a new incident for it. This is intentionally simple (same src_ip +
    event_type within a time window) — swap in a graph/ML-based correlator later.
    """
    if event.src_ip:
        window_start = event.timestamp - CORRELATION_WINDOW
        candidate = (
            db.query(models.Incident)
            .join(models.RawEvent)
            .filter(
                models.RawEvent.src_ip == event.src_ip,
                models.RawEvent.event_type == event.event_type,
                models.RawEvent.timestamp >= window_start,
                models.Incident.status.in_(["open", "investigating"]),
            )
            .first()
        )
        if candidate:
            event.incident_id = candidate.id
            db.commit()
            return candidate

    incident = models.Incident(
        title=f"{event.event_type} from {event.src_ip or 'unknown source'}",
        description=f"Auto-created from {event.source} event.",
        status="open",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    event.incident_id = incident.id
    db.commit()
    return incident
