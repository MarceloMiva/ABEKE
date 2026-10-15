from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/iocs", tags=["iocs"])


@router.get("/", response_model=List[schemas.IOCOut])
def list_iocs(
    ioc_type: Optional[str] = None,
    known_bad: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """The searchable breach knowledge base — query across every IOC ABEKE has ever seen."""
    q = db.query(models.IOC)
    if ioc_type:
        q = q.filter(models.IOC.ioc_type == ioc_type)
    if known_bad:
        q = q.filter(models.IOC.known_bad == known_bad)
    return q.order_by(models.IOC.first_seen.desc()).limit(200).all()
