from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .routers import ingest, incidents, iocs

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="ABEKE",
    description="Automated Breach & Event Knowledge Engine — SOC analysis framework",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this before deploying publicly
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest.router)
app.include_router(incidents.router)
app.include_router(iocs.router)


@app.get("/")
def root():
    return {"name": "ABEKE", "status": "online", "docs": "/docs"}
