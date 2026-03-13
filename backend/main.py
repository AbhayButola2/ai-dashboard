from fastapi import FastAPI, BackgroundTasks, UploadFile, File
import asyncio
import os
import json
import uuid
import shutil
import datetime

from collectors.feodo import fetch_feodo_data
from collectors.blocklist_de import fetch_blocklist_data
from collectors.emerging_threats import fetch_emerging_threats_data
from processing.cleaner import merge_all_sources
from processing.log_parser import parse_raw_logs
from models.ml_classifier import classifier
from generate_raw_logs import main as _gen_raw

app = FastAPI(title="AI Threat Intelligence Dashboard API", version="2.0")

ROOT = os.path.dirname(__file__)
RAW_LOG_PATH  = os.path.join(ROOT, "raw_logs.txt")
NORM_LOG_PATH = os.path.join(ROOT, "normalized_logs.json")

UPLOAD_DIR = os.path.join(ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Simple in-memory cache
cache = {"status": "idle"}

# ── Background pipeline ────────────────────────────────────────────────────────

async def run_pipeline():
    cache["status"] = "updating"
    try:
        # 1. Fetch and write raw logs
        await _gen_raw()

        # 2. Parse raw logs into normalized JSON
        result = parse_raw_logs(RAW_LOG_PATH)
        with open(NORM_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        # 3. Also classify via ML
        import pandas as pd
        df = pd.DataFrame(result["threats"])
        if not df.empty:
            df["ml_severity"] = classifier.predict(df.rename(columns={"threat_type": "threat_type"}))
            # prefer parser severity over ML for now
        cache["last_run"] = result.get("parse_timestamp", "unknown")
        cache["stats"] = {
            "parsed_count":   result["parsed_count"],
            "severity_summary": result["severity_summary"],
            "source_summary":   result["source_summary"],
            "threat_type_summary": result["threat_type_summary"],
        }
    except Exception as e:
        print(f"Pipeline error: {e}")
    finally:
        cache["status"] = "idle"


def _load_normalized() -> dict | None:
    if os.path.exists(NORM_LOG_PATH):
        with open(NORM_LOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/v1/update")
async def trigger_update(background_tasks: BackgroundTasks):
    if cache["status"] == "updating":
        return {"message": "Update already in progress."}
    background_tasks.add_task(run_pipeline)
    return {"message": "Pipeline started in the background."}

@app.post("/api/v1/upload")
async def upload_custom_logs(file: UploadFile = File(...)):
    if cache["status"] == "updating":
        return {"error": "Pipeline is busy. Please wait.", "status": "error"}
    
    file_id = str(uuid.uuid4())
    ext = os.path.splitext(file.filename)[1].lower()
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}{ext}")
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        if ext == ".json":
            with open(temp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            threats = data.get("threats", data) if isinstance(data, dict) else data
            if not isinstance(threats, list):
                threats = [{"raw_line": str(threats), "severity": "Unknown", "source": "Custom JSON"}]
                
            result = {
                "parse_timestamp": datetime.datetime.utcnow().isoformat(),
                "raw_file": file.filename,
                "parsed_count": len(threats),
                "severity_summary": {},
                "source_summary": {"Custom JSON": len(threats)},
                "threat_type_summary": {},
                "threats": threats
            }
            for r in threats:
                sev = r.get("severity", "Unknown")
                r["source"] = r.get("source", "Custom JSON")
                result["severity_summary"][sev] = result["severity_summary"].get(sev, 0) + 1
        else:
            # Parse it strictly through the raw log parser, which now catches generics
            result = parse_raw_logs(temp_path)
            result["source_summary"] = {"Custom Text/Log": result["parsed_count"]}
            # overwrite the source manually
            for r in result["threats"]:
                if r["source"] == "Custom Upload":
                    r["source"] = "User Uploaded Txt"
            
        # Overwrite current active normalization file so dashboard displays it immediately
        with open(NORM_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
            
        cache["last_run"] = result["parse_timestamp"]
        return {"message": f"Successfully processed {file.filename}.", "parsed_count": result["parsed_count"]}
    except Exception as e:
        return {"error": str(e), "status": "error"}


@app.get("/api/v1/threats")
async def get_threats():
    data = _load_normalized()
    if not data:
        return {"status": "no_data", "data": []}
    return {
        "status": cache["status"],
        "parse_timestamp": data.get("parse_timestamp"),
        "raw_file": data.get("raw_file"),
        "total_raw_lines": data.get("total_raw_lines"),
        "parsed_count": data.get("parsed_count"),
        "skipped_count": data.get("skipped_count"),
        "data": data.get("threats", []),
    }


@app.get("/api/v1/stats")
async def get_stats():
    data = _load_normalized()
    if not data:
        return {"total_threats": 0, "severities": {}, "sources": {}, "threat_types": {}}
    return {
        "total_threats":   data.get("parsed_count", 0),
        "raw_lines":       data.get("total_raw_lines", 0),
        "skipped":         data.get("skipped_count", 0),
        "severities":      data.get("severity_summary", {}),
        "sources":         data.get("source_summary", {}),
        "threat_types":    data.get("threat_type_summary", {}),
        "parse_timestamp": data.get("parse_timestamp", ""),
    }


@app.get("/api/v1/raw")
async def get_raw_log():
    """Return the raw log file as plain text."""
    if not os.path.exists(RAW_LOG_PATH):
        return {"error": "raw_logs.txt not found. Run /api/v1/update first."}
    with open(RAW_LOG_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    return {"content": content, "lines": len(content.splitlines())}
