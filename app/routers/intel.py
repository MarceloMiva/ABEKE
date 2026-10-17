from fastapi import APIRouter
from ..services import threat_intel

router = APIRouter(prefix="/intel", tags=["intel"])


@router.post("/update")
def update_intel(min_confidence: int = 2):
    return threat_intel.update_feed(min_confidence)


@router.get("/status")
def intel_status():
    return threat_intel.status()
