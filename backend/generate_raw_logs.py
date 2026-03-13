"""
generate_raw_logs.py
--------------------
Fetches live data from all 3 free threat feeds and writes it as a
realistic, multi-format, unstructured raw security log file (raw_logs.txt).

This simulates what a real SOC would receive BEFORE any normalization:
  - Feodo Tracker  → mixed CSV/syslog style lines
  - Blocklist.de   → firewall BLOCK log style
  - Emerging Threats → snort/IDS alert style

Run: python generate_raw_logs.py
"""

import asyncio
import sys
import os
from datetime import datetime, timedelta
import random

sys.path.insert(0, os.path.dirname(__file__))
from collectors.feodo import fetch_feodo_data
from collectors.blocklist_de import fetch_blocklist_data
from collectors.emerging_threats import fetch_emerging_threats_data

# Slight time offset helpers for realistic timestamps
def ts(offset_hours=0):
    dt = datetime.utcnow() - timedelta(hours=offset_hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def syslog_ts(offset_hours=0):
    dt = datetime.utcnow() - timedelta(hours=offset_hours)
    return dt.strftime("%b %d %H:%M:%S")

async def main():
    out_path = os.path.join(os.path.dirname(__file__), "raw_logs.txt")

    print("Fetching live threat data from 3 sources...")
    feodo, blocklist, et = await asyncio.gather(
        fetch_feodo_data(limit=10),
        fetch_blocklist_data(limit=80),
        fetch_emerging_threats_data(limit=40),
    )
    print(f"  Feodo: {len(feodo)} | Blocklist.de: {len(blocklist)} | EmergingThreats: {len(et)}")

    lines = []

    # ── SECTION 1: Feodo Tracker raw export (CSV-like, comment-headed) ──────────
    lines.append("# ============================================================")
    lines.append("# Feodo Tracker - Botnet C2 IP Feed")
    lines.append(f"# Generated: {ts()}")
    lines.append("# Fields: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware")
    lines.append("# ============================================================")
    for rec in feodo:
        ioc  = rec.get("ioc", "")
        tags = rec.get("tags", "")
        mal  = rec.get("malware_alias", "Unknown")
        port = tags.split("port ")[-1] if "port " in tags else "443"
        raw_ts = rec.get("timestamp", ts(random.randint(1, 48)))
        # raw CSV row (noisy: some have extra space, inconsistent quoting)
        lines.append(f'{raw_ts},{ioc},{port},online,{ts(random.randint(100,200))},{mal}')

    lines.append("")

    # ── SECTION 2: Blocklist.de — firewall BLOCK alert format ───────────────────
    lines.append("# ============================================================")
    lines.append("# Blocklist.de - Attacker IP block log")
    lines.append(f"# exported={ts()}  format=syslog")
    lines.append("# ============================================================")
    reporters = ["fw01.corp", "edge-gw", "honeypot-us-east", "ids-sensor-02", "siem-relay"]
    attack_types = ["SSH_BRUTE_FORCE", "FTP_BRUTE_FORCE", "SMTP_AUTH_ABUSE", "RDP_SCAN", "HTTP_FLOOD"]
    dsts = ["10.0.0.1", "192.168.1.254", "172.16.0.10"]
    for i, rec in enumerate(blocklist):
        ip   = rec.get("ioc", "")
        atk  = attack_types[i % len(attack_types)]
        host = reporters[i % len(reporters)]
        dst  = dsts[i % len(dsts)]
        sev  = "CRIT" if i % 5 == 0 else "WARN"
        # Syslog style — real logs look messy like this
        lines.append(
            f'{syslog_ts(i//10)} {host} kernel: [{sev}] BLOCK '
            f'src={ip} dst={dst} proto=TCP dport=22 reason="{atk}" count={random.randint(3,200)}'
        )

    lines.append("")

    # ── SECTION 3: Emerging Threats — IDS/SNORT alert style ────────────────────
    lines.append("# ============================================================")
    lines.append("# EmergingThreats - Compromised Host Intelligence")
    lines.append(f"# Feed date: {datetime.utcnow().strftime('%Y-%m-%d')}")
    lines.append("# Format: ALERT | timestamp | src_ip | category | description")
    lines.append("# ============================================================")
    categories = [
        "MALWARE-DISTRIBUTION", "BOTNET-MEMBER", "EXPLOIT-KIT",
        "DDoS-SOURCE", "PHISHING-HOST", "CRYPTOMINER"
    ]
    for i, rec in enumerate(et):
        ip   = rec.get("ioc", "")
        cat  = categories[i % len(categories)]
        sig  = f"ET COMPROMISED Known Compromised Host Traffic ({cat})"
        port = random.choice([80, 443, 8080, 4444, 6666])
        # Snort/IDS alert style — pipe-delimited, sometimes extra metadata appended
        lines.append(
            f'ALERT | {ts(i//5)} | {ip} | {cat} | {sig} | '
            f'dst_port={port} | priority={"1" if "MALWARE" in cat or "EXPLOIT" in cat else "2"}'
        )

    lines.append("")
    lines.append(f"# END OF LOG EXPORT  total_entries={len(feodo)+len(blocklist)+len(et)}")
    lines.append(f"# Dump timestamp: {ts()}")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nWritten {len(lines)} lines -> raw_logs.txt")
    print(f"File: {out_path}")

if __name__ == "__main__":
    asyncio.run(main())
