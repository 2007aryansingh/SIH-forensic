from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from uuid import uuid4

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from weasyprint import HTML as WeasyHTML
except Exception:  # pragma: no cover - environment-specific fallback
    WeasyHTML = None

from forensic.report_models import ForensicReportContext

TEMPLATE_DIR = Path(__file__).parent


def load_report_template():
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    return env.get_template("report_template.html")


def render_report(context: ForensicReportContext) -> str:
    template = load_report_template()
    return template.render(**context.model_dump(mode="json"))


def _build_reportlab_pdf(context: ForensicReportContext) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Project Sentinel", styles['Title']),
        Paragraph("Email Forensic Analysis Report", styles['Heading1']),
        Spacer(1, 12),
        Paragraph(f"Email ID: {context.email_id}", styles['BodyText']),
        Paragraph(f"Risk Score: {context.risk_score}/100", styles['BodyText']),
        Paragraph(f"Verdict: {context.verdict}", styles['BodyText']),
        Paragraph(f"Evidence SHA-256: {context.evidence.sha256}", styles['BodyText']),
        Paragraph(f"Generated: {context.generated_at.isoformat()}", styles['BodyText']),
        Spacer(1, 12),
        Paragraph(f"Authentication: SPF={context.authentication.get('spf', 'NOT_CHECKED')} DKIM={context.authentication.get('dkim', 'NOT_CHECKED')} DMARC={context.authentication.get('dmarc', 'NOT_CHECKED')}", styles['BodyText']),
        Paragraph(f"Origin Trace: {context.origin_trace.get('probable_origin_ip', 'unknown') if context.origin_trace else 'unknown'}", styles['BodyText']),
        Paragraph(f"Domain: {context.domain_intel.get('domain', 'unknown') if context.domain_intel else 'unknown'}", styles['BodyText']),
    ]

    if context.limitations:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Limitations:", styles['Heading2']))
        for item in context.limitations:
            story.append(Paragraph(f"- {item}", styles['BodyText']))

    doc.build(story)
    return buffer.getvalue()


def generate_report_bytes(context: ForensicReportContext) -> bytes:
    html = render_report(context)
    if WeasyHTML is not None:
        return WeasyHTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
    return _build_reportlab_pdf(context)


async def build_report_context(email_id: str, storage) -> ForensicReportContext:
    email = await storage.get_email_analysis_async(email_id)
    if email is None:
        raise ValueError(f"Email analysis not found for {email_id}")

    evidence = await storage.get_evidence_metadata_async(email_id)
    if evidence is None:
        raise ValueError("Evidence metadata is missing for this email")

    risk_score = email.get("risk_score", 0)
    risk_level = email.get("risk_level", "unknown")
    verdict = email.get("verdict", "UNKNOWN")
    sender = email.get("sender", {})
    authentication = email.get("authentication", {})
    headers = email.get("headers", {})
    origin_trace = email.get("origin_trace") or {"status": "not_available", "reason": "Origin tracing was not performed"}
    domain_intel = email.get("domain_intel") or {"domain": "unknown"}
    indicators = email.get("indicators", [])
    mitre_matches = email.get("mitre_matches", [])
    timeline = email.get("timeline", [])
    limitations = email.get("limitations", [])

    return ForensicReportContext(
        report_id=f"report-{uuid4()}",
        email_id=email_id,
        generated_at=datetime.now(timezone.utc),
        generator_version="1.0.0",
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        evidence=evidence,
        sender=sender,
        authentication=authentication,
        headers=headers,
        origin_trace=origin_trace,
        domain_intel=domain_intel,
        indicators=indicators,
        mitre_matches=mitre_matches,
        timeline=timeline,
        limitations=limitations,
    )


async def generate_report(email_id: str, storage) -> bytes:
    context = await build_report_context(email_id, storage)
    return generate_report_bytes(context)
