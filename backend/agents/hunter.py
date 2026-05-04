"""
agents/hunter.py
-----------------
Phase 6 — Threat Hunter (Safe Mode).

Uses embedding similarity to find logs that closely match known threat patterns.
Does NOT take any automated action.
"""
import logging

logger = logging.getLogger("hunter")

# Known high-risk signatures used as reference queries
THREAT_SIGNATURES = [
    "botnet C2 communication",
    "malware distribution known malicious host",
    "ransomware file encryption lateral movement",
    "SSH brute force repeated failed logins",
    "phishing domain credential harvesting",
    "exploit kit drive-by download",
    "DDoS amplification UDP flood",
    "cryptominer unusual outbound traffic",
]


def hunt(top_k: int = 5) -> list:
    """
    Find logs that match known threat signatures via semantic search.
    Returns a list of hunt results, each with matched signature + top logs.
    """
    try:
        from services.embedder import search_similar
    except Exception as e:
        logger.error(f"Embedder unavailable for hunting: {e}")
        return []

    results = []
    for sig in THREAT_SIGNATURES:
        try:
            matches = search_similar(sig, top_k=top_k)
            if matches:
                results.append({
                    "signature": sig,
                    "matched_logs": matches[:3],   # top 3 per signature
                    "max_similarity": matches[0]["similarity_score"] if matches else 0.0,
                })
        except Exception as e:
            logger.warning(f"Hunt for '{sig}' failed: {e}")

    # Sort by highest similarity first
    results.sort(key=lambda x: x["max_similarity"], reverse=True)
    return results
