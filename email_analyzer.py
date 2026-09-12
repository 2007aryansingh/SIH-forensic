from __future__ import annotations

import re
from typing import List

from intelligence import detect_scam, extract_intelligence
from lifecycle import ScamPhase
from scoring import compute_risk_score
from schemas import EmailAnalysisRequest, EmailAnalysisResponse, EmailIndicator


URGENCY_WORDS = {
    "urgent",
    "immediately",
    "now",
    "today",
    "asap",
    "suspend",
    "blocked",
    "expire",
    "final notice",
}
PAYMENT_WORDS = {
    "pay",
    "payment",
    "transfer",
    "upi",
    "bank",
    "account verification",
    "kyc",
}
BRAND_SPOOF_WORDS = {"bank", "support", "security team", "verification", "official"}


def _collect_text(payload: EmailAnalysisRequest) -> str:
    parts = [
        payload.from_name or "",
        payload.from_email,
        payload.subject or "",
        payload.message_text,
        " ".join(payload.links),
    ]
    return " ".join(p for p in parts if p).strip()


def _contains_any(text: str, words: set[str]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


def _looks_suspicious_sender(email: str, display_name: str | None) -> bool:
    local_domain = email.split("@")[-1].lower() if "@" in email else email.lower()
    disposable_like = local_domain.endswith((".xyz", ".top", ".click", ".biz"))
    brand_like_name = bool(display_name and _contains_any(display_name, BRAND_SPOOF_WORDS))
    suspicious_chars = bool(re.search(r"\d{3,}", local_domain))
    return disposable_like or (brand_like_name and suspicious_chars)


def _phase_from_content(text: str) -> ScamPhase:
    lower = text.lower()
    if _contains_any(lower, PAYMENT_WORDS):
        return ScamPhase.PAYMENT
    if "http://" in lower or "https://" in lower or "www." in lower:
        return ScamPhase.ESCALATION
    if _contains_any(lower, URGENCY_WORDS):
        return ScamPhase.PRESSURE
    return ScamPhase.INITIAL


def _build_reasons(
    payload: EmailAnalysisRequest,
    intelligence,
    indicators: List[EmailIndicator],
) -> List[str]:
    reasons: List[str] = []
    text = _collect_text(payload).lower()

    if _contains_any(text, URGENCY_WORDS):
        reasons.append("Urgency language detected")
        indicators.append(EmailIndicator(key="urgency", value="true"))

    if intelligence and intelligence.phishing_links:
        reasons.append("Suspicious link/domain detected")
        indicators.append(EmailIndicator(key="phishing_links", value=str(len(intelligence.phishing_links))))

    if _contains_any(text, PAYMENT_WORDS):
        reasons.append("Payment/account-verification intent detected")
        indicators.append(EmailIndicator(key="payment_intent", value="true"))

    if _looks_suspicious_sender(payload.from_email, payload.from_name):
        reasons.append("Sender identity appears suspicious")
        indicators.append(EmailIndicator(key="sender_reputation", value="suspicious"))

    return reasons[:3]


def _scam_type(reasons: List[str], intelligence) -> str | None:
    if not reasons:
        return None
    if intelligence and intelligence.upi_ids:
        return "payment_fraud"
    if intelligence and intelligence.phishing_links:
        return "phishing_or_payment_fraud"
    return "social_engineering"


def analyze_email(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:
    combined_text = _collect_text(payload)
    detection = detect_scam(combined_text)
    intelligence = extract_intelligence(combined_text) if detection.is_scam else extract_intelligence(payload.message_text)

    fingerprint = {
        "pressure_language": _contains_any(combined_text, URGENCY_WORDS),
        "links_shared": bool((payload.links or []) or (intelligence and intelligence.phishing_links)),
        "payment_intent": _contains_any(combined_text, PAYMENT_WORDS),
        "message_count": 1,
    }
    phase = _phase_from_content(combined_text)
    risk = compute_risk_score(detection=detection, fingerprint=fingerprint, phase=phase, intelligence=intelligence)

    indicators: List[EmailIndicator] = []
    reasons = _build_reasons(payload, intelligence, indicators)
    scam_type = _scam_type(reasons, intelligence) if detection.is_scam else None

    return EmailAnalysisResponse(
        is_scam=detection.is_scam,
        confidence=detection.confidence,
        risk=risk,
        scam_type=scam_type,
        reasons=reasons,
        extracted_intelligence=intelligence,
    )
