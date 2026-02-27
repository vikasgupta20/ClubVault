"""
chatbot.py - Platform Navigation Chatbot
==========================================
Phase 8: Helps users and hosts navigate the platform.
  - Rule-based responses for common questions
  - Optional Gemini API integration for complex queries
"""

import os
import re
import httpx

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# ── Rule-Based Knowledge Base ─────────────────────────────
RULES = [
    {
        "patterns": [r"how\s+(to|do\s+i)\s+request\s+access", r"request\s+access", r"get\s+access"],
        "response": (
            "To request access to a project:\n"
            "1. Go to your Dashboard\n"
            "2. Browse available projects\n"
            "3. Click 'Request Access'\n"
            "4. Select your desired permissions and duration (up to 2 hours)\n"
            "5. Submit the request — the host will review it along with your AI risk score"
        ),
    },
    {
        "patterns": [r"extend\s+(time|access|session|duration)", r"how\s+to\s+extend", r"more\s+time"],
        "response": (
            "When your access token expires:\n"
            "1. A 'Request Extension' button will appear on your dashboard\n"
            "2. Click it and specify the additional time needed\n"
            "3. The host must approve the extension before access is restored"
        ),
    },
    {
        "patterns": [r"why\s+(was|is)\s+(my\s+)?access\s+denied", r"access\s+denied", r"denied"],
        "response": (
            "Access can be denied for several reasons:\n"
            "• High risk score from the AI analysis\n"
            "• Suspicious request timing or location\n"
            "• Too many recent requests (rate limiting)\n"
            "• Host manually denied the request\n"
            "• Your account may be temporarily frozen\n\n"
            "Check with your project host for specific details."
        ),
    },
    {
        "patterns": [r"what\s+is\s+(a\s+)?risk\s+score", r"risk\s+score", r"how\s+is\s+risk\s+calculated"],
        "response": (
            "The risk score (1-100) is calculated by our AI engine analyzing:\n"
            "• Time of request\n"
            "• Your IP address and device\n"
            "• Requested permissions level\n"
            "• Your access frequency\n"
            "• Account age and history\n\n"
            "Low (1-35) | Medium (36-65) | High (66-100)"
        ),
    },
    {
        "patterns": [r"how\s+to\s+(create|add|new)\s+project", r"create\s+project"],
        "response": (
            "To create a new project:\n"
            "1. Switch to Host mode or register as a host\n"
            "2. Go to the Host Dashboard\n"
            "3. Click 'Create New Project'\n"
            "4. Enter the project name and description\n"
            "5. Start adding credentials to your project vault"
        ),
    },
    {
        "patterns": [r"what\s+(can|permissions)", r"permissions", r"what\s+access"],
        "response": (
            "Available permission levels:\n"
            "• read — View project files and credentials\n"
            "• write — Modify project resources\n"
            "• admin — Full control (host only)\n\n"
            "Users can only access what the host explicitly approves."
        ),
    },
    {
        "patterns": [r"frozen|freeze|suspended|locked"],
        "response": (
            "If your account is frozen, it means our misuse detection system flagged suspicious activity.\n"
            "This can happen due to:\n"
            "• Too many requests in a short time\n"
            "• Multiple denied access attempts\n"
            "• Abnormal behavior patterns\n\n"
            "Contact your project host to request re-approval."
        ),
    },
    {
        "patterns": [r"credential|vault|secret|api\s*key"],
        "response": (
            "The Credentials Vault securely stores project secrets:\n"
            "• Firebase IDs, GitHub links, API keys, etc.\n"
            "• All values are encrypted with Fernet encryption\n"
            "• Only accessible during active token validity\n"
            "• Hosts can add/remove credentials anytime"
        ),
    },
    {
        "patterns": [r"zero.?trust", r"what\s+is\s+this", r"how\s+does\s+(this|it)\s+work"],
        "response": (
            "Zero-Trust Campus Club Vault follows the 'never trust, always verify' principle:\n"
            "• Every request is authenticated and risk-assessed\n"
            "• Access is temporary and scoped to specific permissions\n"
            "• AI continuously monitors for suspicious behavior\n"
            "• Hosts maintain full control over access decisions\n"
            "• All activity is logged for complete audit trails"
        ),
    },
    {
        "patterns": [r"hi|hello|hey|help|start"],
        "response": (
            "👋 Hello! I'm the Zero-Trust Vault Assistant. I can help you with:\n"
            "• Requesting access to projects\n"
            "• Understanding risk scores\n"
            "• Extending access time\n"
            "• Creating and managing projects\n"
            "• Credential vault usage\n\n"
            "Just ask me anything!"
        ),
    },
]


def rule_based_response(message: str) -> str | None:
    """Match user message against patterns and return a response."""
    message_lower = message.lower().strip()
    for rule in RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, message_lower):
                return rule["response"]
    return None


async def gemini_chat_response(message: str) -> str | None:
    """Use Gemini API for complex questions not covered by rules."""
    if not GEMINI_API_KEY:
        return None

    prompt = f"""You are a helpful assistant for the "Zero-Trust Campus Club Vault" platform.
This platform allows campus clubs to securely share project credentials using zero-trust architecture.
Features include: AI risk scoring, temporary access tokens (0-2 hours), host-controlled access, encrypted credential vaults.

User question: {message}

Provide a helpful, concise response (2-4 sentences max). If the question is unrelated to the platform, politely redirect."""

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GEMINI_URL}?key={GEMINI_API_KEY}",
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.7, "maxOutputTokens": 300},
                },
            )
            if response.status_code == 200:
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        print(f"[Chatbot] Gemini error: {e}")

    return None


async def get_chatbot_response(message: str) -> str:
    """
    Main chatbot entry point.
    1. Try rule-based matching first
    2. Fall back to Gemini API
    3. Default generic response
    """
    # Rule-based first
    response = rule_based_response(message)
    if response:
        return response

    # Try Gemini
    gemini_response = await gemini_chat_response(message)
    if gemini_response:
        return gemini_response

    # Default
    return (
        "I'm not sure about that. Here are some things I can help with:\n"
        "• How to request access\n"
        "• How to extend access time\n"
        "• Why access was denied\n"
        "• Understanding risk scores\n"
        "• Creating projects\n"
        "• Credential vault usage\n\n"
        "Try asking about one of these topics!"
    )
