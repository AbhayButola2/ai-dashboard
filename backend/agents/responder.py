"""
agents/responder.py
--------------------
Phase 6 — Safe Responder (Suggestion-Only Mode).

Generates RECOMMENDED actions based on triage output.
DOES NOT execute anything. All suggestions are human-readable strings.
"""
import logging
from typing import List, Dict

logger = logging.getLogger("responder")

# Action templates per priority level
ACTION_TEMPLATES = {
    "ESCALATE": [
        "🚫 Block IP {ip} immediately — repeated attacker with {severity} severity.",
        "📧 Notify SOC team about persistent threat from {ip} ({threat_type}).",
        "🔍 Investigate lateral movement from {ip} — seen {count}× in logs.",
    ],
    "MONITOR": [
        "👁️ Monitor traffic from {ip} — appeared {count}× in recent logs.",
        "📊 Add {ip} to watchlist for 24-hour observation window.",
    ],
    "FLAG": [
        "⚠️ Flag {ip} for manual review — associated with tag: {tags}.",
        "📝 Log {ip} in threat registry — threat type: {threat_type}.",
    ],
    "NORMAL": [
        "ℹ️ No immediate action required for {ip}.",
    ],
}


def _format_action(template: str, log: dict) -> str:
    return template.format(
        ip          = log.get("ioc") or log.get("source_ip", "N/A"),
        severity    = log.get("severity", "Unknown"),
        threat_type = log.get("threat_type", "unknown"),
        tags        = log.get("tags", "N/A"),
        count       = log.get("ip_seen_count", 1),
    )


def generate_suggestions(triage_result: Dict[str, list]) -> List[dict]:
    """
    Given triage output, return a list of suggested actions.
    Each suggestion: {log_id, priority, suggested_actions: [str], ...}
    """
    suggestions = []

    priority_map = {
        "escalate": "ESCALATE",
        "monitor":  "MONITOR",
        "flag":     "FLAG",
        "normal":   "NORMAL",
    }

    for bucket, priority_key in priority_map.items():
        for log in triage_result.get(bucket, []):
            templates = ACTION_TEMPLATES.get(priority_key, [])
            actions   = [_format_action(t, log) for t in templates]
            suggestions.append({
                "log_id":           log.get("id", log.get("log_id", "")),
                "source_ip":        log.get("ioc") or log.get("source_ip", ""),
                "threat_type":      log.get("threat_type", ""),
                "severity":         log.get("severity", ""),
                "priority":         priority_key,
                "suggested_actions": actions,
                "⚠️_note":          "These are SUGGESTIONS ONLY. No automated action will be taken.",
            })

    # Sort: Escalate first
    order = {"ESCALATE": 0, "FLAG": 1, "MONITOR": 2, "NORMAL": 3}
    suggestions.sort(key=lambda x: order.get(x["priority"], 9))
    return suggestions
