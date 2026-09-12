from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

import storage as storage_module
from api.dependencies import verify_api_key
from forensic.forensic_report import generate_report
from storage import log_report_generation

router = APIRouter()
logger = logging.getLogger("honeypot_api")


def _safe_report_filename(email_id: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "-", email_id or "report")
    candidate = candidate.strip("-_. ") or "report"
    return candidate


@router.get(
    "/emails/{email_id}/report",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}},
)
async def download_forensic_report(email_id: str, api_key: str = Depends(verify_api_key)):
    try:
        pdf_bytes = await generate_report(email_id, storage_module)
    except ValueError as exc:
        message = str(exc)
        if "Evidence metadata" in message:
            raise HTTPException(status_code=409, detail=message)
        raise HTTPException(status_code=404, detail="Email analysis not found")

    log_report_generation(
        event_type="forensic_report_generated",
        email_id=email_id,
        actor="api_user",
        report_id=f"report-{email_id}",
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="forensic-report-{_safe_report_filename(email_id)}.pdf"'
            )
        },
    )


@router.get("/emails/{email_id}/report/metadata")
async def forensic_report_metadata(email_id: str, api_key: str = Depends(verify_api_key)):
    analysis = storage_module.get_email_analysis(email_id)
    evidence = storage_module.get_evidence_metadata(email_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Email analysis not found")
    if evidence is None:
        raise HTTPException(status_code=409, detail="Evidence metadata is missing for this email")

    return {
        "email_id": email_id,
        "report_id": f"report-{email_id}",
        "risk_score": analysis.get("risk_score", 0),
        "verdict": analysis.get("verdict", "UNKNOWN"),
        "evidence": {
            "sha256": evidence.sha256,
            "captured_at": evidence.captured_at.isoformat(),
            "integrity_status": evidence.integrity_status,
        },
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
