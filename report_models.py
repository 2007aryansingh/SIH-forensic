from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class EvidenceMetadata(BaseModel):
    evidence_id: str
    email_id: str
    sha256: str = Field(min_length=64, max_length=64)
    captured_at: datetime
    captured_by: str = "system"
    source: str | None = None
    original_filename: str | None = None
    content_length: int | None = None
    hash_algorithm: str = "SHA-256"
    integrity_status: str = "verified"


class ForensicReportContext(BaseModel):
    report_id: str
    email_id: str
    generated_at: datetime
    generator_version: str

    risk_score: float
    risk_level: str
    verdict: str

    evidence: EvidenceMetadata

    sender: dict
    authentication: dict
    headers: dict
    origin_trace: dict | None = None
    domain_intel: dict | None = None

    indicators: list[dict] = []
    mitre_matches: list[dict] = []
    timeline: list[dict] = []

    limitations: list[str] = []
