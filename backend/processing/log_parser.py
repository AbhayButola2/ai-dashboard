"""
log_parser.py
-------------
Parses the unstructured raw_logs.txt (multi-format) into a clean
normalized_logs.json with a unified schema.

Handles 3 log formats:
  1. Feodo CSV:    timestamp,ip,port,status,last_online,malware
  2. Syslog BLOCK: host kernel: [SEV] BLOCK src=X dst=Y ... reason="ATTACK"
  3. IDS ALERT:   ALERT | timestamp | ip | category | sig | dst_port=X | priority=N

Run: python processing/log_parser.py
"""
import re, json, os
from datetime import datetime

RAW_PATH        = os.path.join(os.path.dirname(__file__), "..", "raw_logs.txt")
NORMALIZED_PATH = os.path.join(os.path.dirname(__file__), "..", "normalized_logs.json")

SEVERITY_MAP = {
    "botnet_cc":            "Critical",
    "SSH_BRUTE_FORCE":      "High",
    "FTP_BRUTE_FORCE":      "Medium",
    "SMTP_AUTH_ABUSE":      "Medium",
    "RDP_SCAN":             "High",
    "HTTP_FLOOD":           "Medium",
    "MALWARE-DISTRIBUTION": "Critical",
    "BOTNET-MEMBER":        "High",
    "EXPLOIT-KIT":          "Critical",
    "DDoS-SOURCE":          "High",
    "PHISHING-HOST":        "Medium",
    "CRYPTOMINER":          "Low",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────

# Feodo CSV: 2022-06-04T21:24:53Z,162.243.103.246,8080,online,...,Emotet
RE_FEODO = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T[\d:]+Z),([0-9.]+),(\d+),(\w+),([^,]+),(.+)$'
)

# Syslog:  Mar 13 14:05:32 fw01 kernel: [CRIT] BLOCK src=1.2.3.4 dst=... reason="..."
RE_SYSLOG = re.compile(
    r'^(\w+ \d+ [\d:]+)\s+([\w.\-]+)\s+kernel:\s+\[(\w+)\]\s+BLOCK\s+'
    r'src=([\d.]+)\s+dst=([\d.]+)\s+proto=(\w+)\s+dport=(\d+)\s+reason="([^"]+)"\s+count=(\d+)'
)

# IDS: ALERT | 2026-03-13T15:00:00Z | 1.2.3.4 | CATEGORY | sig | dst_port=N | priority=N
RE_IDS = re.compile(
    r'^ALERT\s*\|\s*([^|]+)\s*\|\s*([0-9.]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*dst_port=(\d+)\s*\|\s*priority=(\d+)'
)

def parse_feodo(line: str, idx: int) -> dict | None:
    m = RE_FEODO.match(line.strip())
    if not m:
        return None
    ts, ip, port, status, _, malware = m.groups()
    malware = malware.strip()
    return {
        "id":            f"feodo-{idx}",
        "raw_line":      line.strip(),
        "source":        "FeodoTracker",
        "ioc":           ip,
        "ioc_type":      "ip:port",
        "threat_type":   "botnet_cc",
        "malware_alias": malware,
        "dst_port":      int(port),
        "c2_status":     status,
        "severity":      SEVERITY_MAP.get("botnet_cc", "High"),
        "confidence":    90,
        "tags":          f"C2, {malware}, botnet",
        "timestamp":     ts,
    }

def parse_syslog(line: str, idx: int) -> dict | None:
    m = RE_SYSLOG.match(line.strip())
    if not m:
        return None
    ts, host, sev_raw, src_ip, dst_ip, proto, dport, reason, count = m.groups()
    sev = "Critical" if sev_raw == "CRIT" else SEVERITY_MAP.get(reason, "Medium")
    return {
        "id":            f"blde-{idx}",
        "raw_line":      line.strip(),
        "source":        "Blocklist.de",
        "ioc":           src_ip,
        "ioc_type":      "ip",
        "threat_type":   reason,
        "malware_alias": "Unknown",
        "dst_port":      int(dport),
        "dst_ip":        dst_ip,
        "reporter_host": host,
        "event_count":   int(count),
        "severity":      sev,
        "confidence":    70,
        "tags":          f"{reason}, brute_force, {proto}",
        "timestamp":     ts,
    }

def parse_ids(line: str, idx: int) -> dict | None:
    m = RE_IDS.match(line.strip())
    if not m:
        return None
    ts, ip, category, sig, dport, priority = m.groups()
    category = category.strip()
    sev = SEVERITY_MAP.get(category, "Medium")
    return {
        "id":            f"et-{idx}",
        "raw_line":      line.strip(),
        "source":        "EmergingThreats",
        "ioc":           ip,
        "ioc_type":      "ip",
        "threat_type":   category,
        "malware_alias": "Unknown",
        "dst_port":      int(dport),
        "signature":     sig.strip(),
        "severity":      sev,
        "confidence":    80,
        "priority":      int(priority),
        "tags":          f"{category}, compromised_host, ids_alert",
        "timestamp":     ts.strip(),
    }

def parse_generic(line: str, idx: int) -> dict:
    return {
        "id":            f"custom-{idx}",
        "raw_line":      line,
        "source":        "Custom Upload",
        "ioc":           "Unknown",
        "ioc_type":      "unknown",
        "threat_type":   "generic_log",
        "malware_alias": "Unknown",
        "severity":      "Low",
        "confidence":    50,
        "tags":          "custom_log",
        "timestamp":     datetime.utcnow().isoformat()
    }

def parse_raw_logs(path: str) -> dict:
    records   = []
    skipped   = []
    errors    = []
    feodo_i = syslog_i = ids_i = 0

    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    for lineno, line in enumerate(raw_lines, 1):
        line = line.rstrip("\n")
        stripped = line.strip()

        # Skip blank lines and comment/header lines
        if not stripped or stripped.startswith("#"):
            continue

        parsed = None
        try:
            if RE_FEODO.match(stripped):
                parsed = parse_feodo(stripped, feodo_i)
                feodo_i += 1
            elif stripped.startswith("ALERT"):
                parsed = parse_ids(stripped, ids_i)
                ids_i += 1
            elif "BLOCK" in stripped and "src=" in stripped:
                parsed = parse_syslog(stripped, syslog_i)
                syslog_i += 1
            else:
                parsed = parse_generic(stripped, len(records))
        except Exception as e:
            errors.append({"line": lineno, "content": stripped, "error": str(e)})
            continue

        if parsed:
            records.append(parsed)
        else:
            skipped.append({"line": lineno, "content": stripped})

    severity_counts = {}
    source_counts   = {}
    threat_counts   = {}
    for r in records:
        sev = r.get("severity", "Unknown")
        src = r.get("source", "Unknown")
        tt  = r.get("threat_type", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src]   = source_counts.get(src, 0) + 1
        threat_counts[tt]    = threat_counts.get(tt, 0) + 1

    return {
        "parse_timestamp": datetime.utcnow().isoformat(),
        "raw_file":        os.path.basename(path),
        "total_raw_lines": len(raw_lines),
        "parsed_count":    len(records),
        "skipped_count":   len(skipped),
        "error_count":     len(errors),
        "severity_summary":     severity_counts,
        "source_summary":       source_counts,
        "threat_type_summary":  threat_counts,
        "threats":         records,
        "_skipped":        skipped[:20],   # first 20 for debugging
        "_errors":         errors,
    }


if __name__ == "__main__":
    result = parse_raw_logs(os.path.abspath(RAW_PATH))
    with open(os.path.abspath(NORMALIZED_PATH), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Parsed  : {result['parsed_count']} records")
    print(f"Skipped : {result['skipped_count']}")
    print(f"Errors  : {result['error_count']}")
    print(f"Written : normalized_logs.json")
    print(f"Severity: {result['severity_summary']}")
