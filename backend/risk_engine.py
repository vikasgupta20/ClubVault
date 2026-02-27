"""
risk_engine.py - AI-Powered Risk Scoring Engine
=================================================
Implements Phase 3 & Phase 7:
  - Collects contextual signals (time, IP, device, permissions, frequency)
  - Sends structured prompt to Google Gemini API
  - Fallback rule-based scoring if Gemini fails
  - Misuse detection & automatic suspension
"""

import json
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from models import AccessRequest, User, ActivityLog

# ── Gemini API Configuration ─────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


async def analyze_risk_with_gemini(context: dict) -> dict:
    """
    Send risk analysis request to Google Gemini API.
    Returns: { risk_score: int, risk_level: str, explanation: str }
    """
    if not GEMINI_API_KEY:
        return fallback_risk_scoring(context)

    prompt = f"""You are a zero-trust security risk analyzer for a campus club collaboration platform.

Analyze the following access request and return a JSON risk assessment.

Context:
- User: {context.get('username', 'unknown')}
- Requesting permissions: {context.get('permissions', 'read')}
- Requested duration: {context.get('duration', 60)} minutes
- Time of request: {context.get('request_time', 'unknown')}
- IP address: {context.get('ip_address', 'unknown')}
- Device info: {context.get('device_info', 'unknown')}
- Previous access count (last 24h): {context.get('recent_access_count', 0)}
- Previous denials: {context.get('denial_count', 0)}
- Account age: {context.get('account_age_days', 0)} days
- Is first request to this project: {context.get('is_first_request', True)}

Return ONLY valid JSON (no markdown, no code fences):
{{
  "risk_score": <number 1-100>,
  "risk_level": "<Low|Medium|High>",
  "explanation": "<one short sentence explaining the risk assessment>"
}}"""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GEMINI_URL}?key={GEMINI_API_KEY}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.3,
                        "maxOutputTokens": 200,
                    },
                },
            )
            if response.status_code == 200:
                data = response.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                # Extract JSON from response
                text = text.strip()
                # Remove markdown code fences if present
                text = re.sub(r'^```json\s*', '', text)
                text = re.sub(r'\s*```$', '', text)
                result = json.loads(text)
                # Validate
                score = int(result.get("risk_score", 50))
                level = result.get("risk_level", "Medium")
                explanation = result.get("explanation", "AI analysis completed.")
                return {
                    "risk_score": max(1, min(100, score)),
                    "risk_level": level if level in ("Low", "Medium", "High") else "Medium",
                    "explanation": explanation,
                }
    except Exception as e:
        print(f"[RiskEngine] Gemini API error: {e}")

    return fallback_risk_scoring(context)


def fallback_risk_scoring(context: dict) -> dict:
    """
    Rule-based fallback when Gemini is unavailable.
    Scores based on heuristic rules.
    """
    score = 10  # Base score

    # Time-based risk: requests between 1 AM - 5 AM are riskier
    try:
        hour = datetime.now(timezone.utc).hour
        if 1 <= hour <= 5:
            score += 20
    except Exception:
        pass

    # Permission escalation risk
    permissions = context.get("permissions", "read")
    if "admin" in permissions.lower():
        score += 30
    elif "write" in permissions.lower():
        score += 15
    elif "delete" in permissions.lower():
        score += 25

    # Duration risk
    duration = context.get("duration", 60)
    if duration > 90:
        score += 10
    if duration > 110:
        score += 10

    # Frequency risk
    recent = context.get("recent_access_count", 0)
    if recent > 5:
        score += 15
    elif recent > 10:
        score += 25

    # Denial history
    denials = context.get("denial_count", 0)
    if denials > 0:
        score += denials * 10

    # New user risk
    age = context.get("account_age_days", 0)
    if age < 1:
        score += 15
    elif age < 7:
        score += 5

    # First request to project
    if context.get("is_first_request", True):
        score += 5

    score = max(1, min(100, score))

    if score <= 35:
        level = "Low"
        explanation = "Request appears routine with no significant risk indicators."
    elif score <= 65:
        level = "Medium"
        explanation = "Some risk factors detected. Host review recommended."
    else:
        level = "High"
        explanation = "Multiple risk indicators detected. Careful review required."

    return {"risk_score": score, "risk_level": level, "explanation": explanation}


async def build_risk_context(
    db: Session,
    user: User,
    project_id: int,
    permissions: str,
    duration: int,
    ip_address: str,
    device_info: str,
) -> dict:
    """Build the context dictionary for risk analysis."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Count recent access requests
    recent_count = db.query(AccessRequest).filter(
        AccessRequest.requester_id == user.id,
        AccessRequest.request_time >= day_ago,
    ).count()

    # Count denials
    denial_count = db.query(AccessRequest).filter(
        AccessRequest.requester_id == user.id,
        AccessRequest.status == "denied",
    ).count()

    # Check if first request to this project
    prev_requests = db.query(AccessRequest).filter(
        AccessRequest.requester_id == user.id,
        AccessRequest.project_id == project_id,
    ).count()

    # Account age
    account_age = (now - user.created_at.replace(tzinfo=timezone.utc)).days if user.created_at else 0

    return {
        "username": user.username,
        "permissions": permissions,
        "duration": duration,
        "request_time": now.isoformat(),
        "ip_address": ip_address,
        "device_info": device_info,
        "recent_access_count": recent_count,
        "denial_count": denial_count,
        "is_first_request": prev_requests == 0,
        "account_age_days": account_age,
    }


def check_misuse(db: Session, user_id: int) -> bool:
    """
    Phase 7 - Misuse Detection.
    Returns True if misuse is detected and account should be frozen.
    Checks: excessive requests in short time, multiple denials.
    """
    now = datetime.now(timezone.utc)
    ten_min_ago = now - timedelta(minutes=10)

    # Check for excessive requests (>10 in 10 minutes)
    recent_requests = db.query(AccessRequest).filter(
        AccessRequest.requester_id == user_id,
        AccessRequest.request_time >= ten_min_ago,
    ).count()

    if recent_requests > 10:
        return True

    # Check for multiple recent denials (>3 in 1 hour)
    hour_ago = now - timedelta(hours=1)
    recent_denials = db.query(AccessRequest).filter(
        AccessRequest.requester_id == user_id,
        AccessRequest.status == "denied",
        AccessRequest.request_time >= hour_ago,
    ).count()

    if recent_denials >= 3:
        return True

    # Check for suspicious activity logs (>20 actions in 5 minutes)
    five_min_ago = now - timedelta(minutes=5)
    recent_activity = db.query(ActivityLog).filter(
        ActivityLog.user_id == user_id,
        ActivityLog.timestamp >= five_min_ago,
    ).count()

    if recent_activity > 20:
        return True

    return False
