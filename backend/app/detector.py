from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

URGENT_PATTERNS = [
    "act now",
    "immediately",
    "within 24 hours",
    "today only",
    "urgent",
    "final warning",
    "do not delay",
]

CREDENTIAL_PATTERNS = [
    "otp",
    "one time password",
    "recovery code",
    "bank login",
    "bank account details",
    "password",
    "verify your account",
    "security check",
]

FINANCIAL_PATTERNS = [
    "refund",
    "invoice",
    "payment required",
    "wire transfer",
    "bank transfer",
    "claim your payout",
    "unexpected payment",
]

PRIZE_PATTERNS = [
    "you won",
    "free prize",
    "lucky winner",
    "claim your reward",
    "bonus winner",
    "cash giveaway",
]

IMPERSONATION_PATTERNS = [
    "bank of america",
    "paypal security",
    "apple support",
    "google support",
    "microsoft support",
    "amazon account",
    "official notice",
]

SHORTENER_HOSTS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "tiny.cc",
    "rebrand.ly",
]


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _add_indicator(indicators: list[dict[str, str]], kind: str, severity: str, evidence: str, explanation: str) -> None:
    indicators.append({
        "type": kind,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
    })


def _score_url(url: str) -> tuple[int, list[dict[str, str]]]:
    score = 0
    indicators: list[dict[str, str]] = []
    if not url:
        return score, indicators

    lowered = url.lower()

    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}", lowered):
        score += 20
        _add_indicator(indicators, "url_obfuscation", "high", "IP-address format appears in the URL.", "IP-based destinations can be used to hide a real service domain.")

    if any(host in lowered for host in SHORTENER_HOSTS):
        score += 15
        _add_indicator(indicators, "shortened_link", "medium", "Shortened link host detected.", "Short links can hide the final destination and should be verified carefully.")

    if re.search(r"(?:javascript:|data:|vbscript:)", lowered):
        score += 25
        _add_indicator(indicators, "unsafe_scheme", "high", "The link uses a script-like or unsafe URL scheme.", "URLs using javascript: or data: are often used for deceptive or malicious behavior.")

    if re.search(r"(?:login|verify|secure|account|bank).*(?:\.|/).{0,30}(?:verify|login|secure|update)", lowered):
        score += 10
        _add_indicator(indicators, "suspicious_link_text", "medium", "The link text and destination suggest credential collection.", "Credential-harvesting pages often use security language tied to a mismatched destination.")

    return min(score, 60), indicators


def analyze_content(url: str = "", text: str = "", links: list[dict[str, str]] | None = None) -> dict[str, Any]:
    cleaned_text = (text or "").strip()
    lowered = cleaned_text.lower()
    links = links or []
    indicators: list[dict[str, str]] = []
    score = 0

    if not cleaned_text and not url and not links:
        return {
            "status": "not_analyzed",
            "risk_score": 0,
            "risk_level": "low",
            "summary": "No content available to analyze.",
            "indicators": [],
            "recommendations": [
                "Open a page or provide a URL and text to evaluate.",
                "Use the extension to inspect the active page content.",
            ],
            "analyzed_at": _iso_now(),
            "engine": "rules",
        }

    for pattern in URGENT_PATTERNS:
        if pattern in lowered:
            score += 15
            _add_indicator(indicators, "urgency", "medium", f"Urgent language found: {pattern}.", "Time-pressure language can cause users to act before verifying the source.")
            break

    for pattern in CREDENTIAL_PATTERNS:
        if pattern in lowered:
            score += 18
            _add_indicator(indicators, "credential_request", "high", f"Sensitive-information language found: {pattern}.", "Requests for passwords, OTPs, or recovery codes are common scam patterns.")
            break

    for pattern in FINANCIAL_PATTERNS:
        if pattern in lowered:
            score += 12
            _add_indicator(indicators, "financial_pressure", "medium", f"Financial language detected: {pattern}.", "Unexpected payment or refund demands can be a sign of fraud.")
            break

    for pattern in PRIZE_PATTERNS:
        if pattern in lowered:
            score += 18
            _add_indicator(indicators, "prize_scam", "high", f"Prize claim language detected: {pattern}.", "Unexpected winnings claims often lead to requests for a fee or private details.")
            break

    for pattern in IMPERSONATION_PATTERNS:
        if pattern in lowered:
            score += 16
            _add_indicator(indicators, "impersonation_language", "high", f"Impersonation pattern matched: {pattern}.", "Scammers often impersonate banks or major platforms to gain trust quickly.")
            break

    if re.search(r"(suspend|locked|deactivated|verify now|immediate action)", lowered):
        score += 12
        _add_indicator(indicators, "account_security", "medium", "Account-security warning language detected.", "Urgent account warnings can be used to pressure a user into clicking a deceptive link.")

    url_score, url_indicators = _score_url(url)
    score += url_score
    indicators.extend(url_indicators)

    for link in links[:10]:
        href = (link or {}).get("url", "")
        text_value = (link or {}).get("text", "")
        if not href:
            continue
        link_lower = href.lower()
        if any(host in link_lower for host in SHORTENER_HOSTS):
            score += 10
            _add_indicator(indicators, "shortened_link", "medium", f"Shortened destination found: {href}.", "Shortened URLs hide the final destination and should be checked carefully.")
        if text_value and href and text_value.lower() not in href.lower() and re.search(r"(verify|login|secure|update|alert)", text_value.lower()):
            score += 8
            _add_indicator(indicators, "link_text_mismatch", "medium", "The visible link text does not match the destination purpose.", "Mismatched link text can be a tactic to make a malicious destination appear trustworthy.")

    unique_indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for indicator in indicators:
        key = (indicator["type"], indicator["severity"], indicator["evidence"])
        if key not in seen:
            seen.add(key)
            unique_indicators.append(indicator)
    indicators = unique_indicators

    score = max(0, min(score, 100))

    if score >= 75:
        risk_level = "critical"
        status = "high_risk"
        summary = "High-risk indicators suggest a potentially dangerous page or message."
    elif score >= 45:
        risk_level = "medium"
        status = "suspicious"
        summary = "Several suspicious indicators were detected. Verify the page before taking action."
    elif score > 0:
        risk_level = "low"
        status = "suspicious"
        summary = "Minor suspicious indicators were detected. Review before proceeding."
    else:
        risk_level = "low"
        status = "no_suspicious_indicators_detected"
        summary = "No suspicious indicators detected."

    recommendations = [
        "Verify the sender or site through an official channel before entering credentials.",
        "Do not click links from urgent or pressure-based messaging without confirming the destination.",
    ]
    if indicators:
        recommendations.insert(0, "Review the risk explanations above before entering sensitive information.")

    return {
        "status": status,
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "indicators": indicators,
        "recommendations": recommendations,
        "analyzed_at": _iso_now(),
        "engine": "rules",
    }
