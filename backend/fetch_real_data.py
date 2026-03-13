"""
fetch_real_data.py
------------------
Fetches LIVE data from 3 confirmed free/no-auth sources:
  1. Feodo Tracker (botnet C2 IPs)
  2. Blocklist.de (brute-force attacker IPs)
  3. Emerging Threats (compromised IPs)

Runs ML classifier on all records and saves to demo_logs.json.
Run:  python fetch_real_data.py
"""
import asyncio, json, sys, os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from collectors.feodo import fetch_feodo_data
from collectors.blocklist_de import fetch_blocklist_data
from collectors.emerging_threats import fetch_emerging_threats_data
from processing.cleaner import merge_all_sources
from models.ml_classifier import classifier

async def main():
    print("=" * 60)
    print("  AI Threat Intelligence — Live Data Fetch (3 Sources)")
    print("=" * 60)

    print("\n[1/4] Feodo Tracker (botnet C2 IPs)...")
    feodo = await fetch_feodo_data(limit=50)
    print(f"      → {len(feodo)} records")

    print("\n[2/4] Blocklist.de (brute-force attacker IPs)...")
    blocklist = await fetch_blocklist_data(limit=100)
    print(f"      → {len(blocklist)} records")

    print("\n[3/4] Emerging Threats (compromised IPs)...")
    et = await fetch_emerging_threats_data(limit=50)
    print(f"      → {len(et)} records")

    total_raw = len(feodo) + len(blocklist) + len(et)
    print(f"\n[4/4] Cleaning & merging {total_raw} records...")
    df = merge_all_sources(feodo, blocklist, et)
    print(f"      → {len(df)} after normalization")

    print("\n[5/5] Running Random Forest ML classifier...")
    severities = classifier.predict(df)
    df['ml_severity'] = severities
    print(f"      → Classification complete")

    records = df.to_dict(orient="records")

    severity_counts = {}
    source_counts = {}
    threat_type_counts = {}
    for r in records:
        sev = r.get("ml_severity", "Unknown")
        src = r.get("source", "Unknown")
        tt  = r.get("threat_type", "Unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        source_counts[src]   = source_counts.get(src, 0) + 1
        threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1

    output = {
        "fetch_timestamp": datetime.now().isoformat(),
        "sources_raw_counts": {
            "FeodoTracker": len(feodo),
            "Blocklist.de": len(blocklist),
            "EmergingThreats": len(et)
        },
        "total_records": len(records),
        "severity_summary": severity_counts,
        "source_summary": source_counts,
        "threat_type_summary": threat_type_counts,
        "threats": records
    }

    out_path = os.path.join(os.path.dirname(__file__), "demo_logs.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"  ✅  Saved {len(records)} classified threats to demo_logs.json")
    print(f"  Severity: {severity_counts}")
    print(f"  Sources:  {source_counts}")
    print(f"  Threats:  {threat_type_counts}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
