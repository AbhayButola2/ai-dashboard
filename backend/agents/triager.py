"""
agents/triager.py
------------------
Phase 6 — Rule-Based Triager (Safe Mode).

Applies deterministic rules to prioritize logs:
  - High/Critical severity + repeated source IP → Escalate
  - Known malicious tags → Flag
  - Repeated attacker IP (>1 occurrence) → Monitor
"""
import logging
from collections import Counter
from typing import List, Dict

logger = logging.getLogger("triager")

MALICIOUS_TAGS = {
    "C2", "botnet", "ransomware", "exploit-kit", "malware",
    "phishing", "ddos", "cryptominer", "brute_force",
}

HIGH_SEVERITY = {"Critical", "High"}


def triage(logs: List[dict]) -> Dict[str, list]:
    """
    Triage logs into priority buckets.
    Returns:
        {
            "escalate":  [...],   # High/Critical + repeated IP or known malicious tag
            "monitor":   [...],   # Repeated attacker IPs
            "flag":      [...],   # Contains known malicious tags
            "normal":    [...],   # Everything else
        }
    """
    # Count IP occurrences
    ip_counter = Counter(
        log.get("ioc") or log.get("source_ip", "") for log in logs
    )
    repeated_ips = {ip for ip, cnt in ip_counter.items() if cnt > 1 and ip}

    escalate, monitor, flag, normal = [], [], [], []

    for log in logs:
        ip       = log.get("ioc") or log.get("source_ip", "")
        severity = log.get("severity", "Unknown")
        tags_raw = log.get("tags", "")
        tags_set = {t.strip().lower() for t in str(tags_raw).split(",")}
        has_malicious_tag = bool(tags_set & {t.lower() for t in MALICIOUS_TAGS})

        enriched = {
            **log,
            "triage_flags": [],
            "ip_seen_count": ip_counter.get(ip, 1),
        }

        if severity in HIGH_SEVERITY and (ip in repeated_ips or has_malicious_tag):
            enriched["triage_flags"].append("ESCALATE")
            escalate.append(enriched)
        elif ip in repeated_ips:
            enriched["triage_flags"].append("MONITOR")
            monitor.append(enriched)
        elif has_malicious_tag:
            enriched["triage_flags"].append("FLAG")
            flag.append(enriched)
        else:
            normal.append(enriched)

    logger.info(
        f"Triage complete: {len(escalate)} escalate, {len(monitor)} monitor, "
        f"{len(flag)} flag, {len(normal)} normal"
    )
    return {
        "escalate": escalate[:20],
        "monitor":  monitor[:20],
        "flag":     flag[:20],
        "normal":   normal[:10],
    }
