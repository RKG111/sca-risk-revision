"""
SCA Risk Rescoring Platform — FastAPI entry point.

Endpoints:
  POST /api/v1/analyze        Submit an SBOM + codebase path for rescoring
  GET  /api/v1/reports/{id}   Retrieve a completed rescoring report
  GET  /health                Service health check
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import analysis, reports
from api.config import settings

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SCA Risk Rescoring Platform starting up")
    logger.info("LLMaS endpoint: %s", settings.llmas_base_url)
    yield
    logger.info("Shutting down")


app = FastAPI(
    title="SCA Risk Rescoring Platform",
    description=(
        "Context-aware vulnerability rescoring that replaces generic NVD CVSS scores "
        "with evidence-backed assessments derived from your actual codebase and deployment."
    ),
    version="0.1.0-poc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "version": app.version}
