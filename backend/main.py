"""
main.py  — AI Threat Intelligence Dashboard API  v3.0
=====================================================
Backward-compatible extension of v2.0.

NEW in v3.0 (Phases 1–8):
  - SQLite storage via SQLAlchemy (with JSON backup)
  - Queue-based ingestion worker (replaces BackgroundTasks)
  - Semantic search (/api/v1/search)
  - Graph layer (/api/v1/graph)
  - GNN anomaly detection (/api/v1/anomalies)
  - Combined insights (/api/v1/insights)

PRESERVED from v2.0:
  - /api/v1/threats
  - /api/v1/stats
  - /api/v1/raw
  - /api/v1/update
  - /api/v1/upload
"""

import asyncio
import os
import json
import uuid
import shutil
import datetime
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks, UploadFile, File, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

# ── Existing imports (unchanged) ──────────────────────────────────────────────
from collectors.feodo import fetch_feodo_data
from collectors.blocklist_de import fetch_blocklist_data
from collectors.emerging_threats import fetch_emerging_threats_data
from processing.cleaner import merge_all_sources
from processing.log_parser import parse_raw_logs
from models.ml_classifier import classifier
from generate_raw_logs import main as _gen_raw

# ── New imports (Phase 1–8) ────────────────────────────────────────────────────
from db.database import init_db, get_db
from db import crud
from ingestion_worker import ingestion_queue, start_worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("main")

ROOT          = os.path.dirname(__file__)
RAW_LOG_PATH  = os.path.join(ROOT, "raw_logs.txt")
NORM_LOG_PATH = os.path.join(ROOT, "normalized_logs.json")
UPLOAD_DIR    = os.path.join(ROOT, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initialising database …")
    init_db()
    logger.info("Starting ingestion worker …")
    start_worker()
    yield
    # Shutdown (nothing special needed — worker is daemon)
    logger.info("Shutting down.")


app = FastAPI(
    title="AI Threat Intelligence Dashboard API",
    version="3.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory cache (kept for compatibility)
cache = {"status": "idle"}


# ── Internal pipeline (now queue-aware) ───────────────────────────────────────

async def run_pipeline():
    """Fetch data → parse → enqueue for worker (which persists to DB + JSON)."""
    cache["status"] = "updating"
    try:
        await _gen_raw()

        result = parse_raw_logs(RAW_LOG_PATH)

        # ML classify
        import pandas as pd
        df = pd.DataFrame(result["threats"])
        if not df.empty:
            df["ml_severity"] = classifier.predict(df)
            result["threats"] = df.to_dict(orient="records")

        cache["last_run"] = result.get("parse_timestamp", "unknown")
        cache["stats"] = {
            "parsed_count":       result["parsed_count"],
            "severity_summary":   result["severity_summary"],
            "source_summary":     result["source_summary"],
            "threat_type_summary": result["threat_type_summary"],
        }

        # Enqueue for worker (DB persist + embedding)
        meta = {k: v for k, v in result.items() if k != "threats"}
        ingestion_queue.put({"records": result["threats"], "meta": meta})

    except Exception as e:
        logger.error(f"Pipeline error: {e}")
    finally:
        cache["status"] = "idle"


def _load_normalized() -> dict | None:
    """Legacy JSON loader — used as fallback when DB is empty."""
    if os.path.exists(NORM_LOG_PATH):
        with open(NORM_LOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


# ── Existing Endpoints (unchanged behaviour) ──────────────────────────────────

@app.get("/api/v1/update", tags=["pipeline"])
async def trigger_update(background_tasks: BackgroundTasks):
    if cache["status"] == "updating":
        return {"message": "Update already in progress."}
    background_tasks.add_task(run_pipeline)
    return {"message": "Pipeline started in the background."}


@app.post("/api/v1/upload", tags=["pipeline"])
async def upload_custom_logs(file: UploadFile = File(...)):
    if cache["status"] == "updating":
        return {"error": "Pipeline is busy. Please wait.", "status": "error"}

    file_id  = str(uuid.uuid4())
    ext      = os.path.splitext(file.filename)[1].lower()
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
                "threats": threats,
            }
            for r in threats:
                sev = r.get("severity", "Unknown")
                r["source"] = r.get("source", "Custom JSON")
                result["severity_summary"][sev] = result["severity_summary"].get(sev, 0) + 1
        else:
            result = parse_raw_logs(temp_path)
            result["source_summary"] = {"Custom Text/Log": result["parsed_count"]}
            for r in result["threats"]:
                if r["source"] == "Custom Upload":
                    r["source"] = "User Uploaded Txt"

        # Write JSON backup immediately (for frontend compatibility)
        with open(NORM_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        cache["last_run"] = result["parse_timestamp"]

        # Enqueue to worker for DB + embeddings
        meta = {k: v for k, v in result.items() if k != "threats"}
        ingestion_queue.put({"records": result["threats"], "meta": meta})

        return {"message": f"Successfully processed {file.filename}.", "parsed_count": result["parsed_count"]}
    except Exception as e:
        return {"error": str(e), "status": "error"}


@app.get("/api/v1/threats", tags=["data"])
async def get_threats(db: Session = Depends(get_db)):
    """Returns threats from SQLite (falls back to JSON if DB is empty)."""
    entries = crud.get_all_logs(db, limit=500)

    if entries:
        data = [e.to_dict() for e in entries]
        return {
            "status":         cache["status"],
            "parse_timestamp": cache.get("last_run", ""),
            "parsed_count":   len(data),
            "data":           data,
        }

    # Fallback to JSON
    json_data = _load_normalized()
    if not json_data:
        return {"status": "no_data", "data": []}
    return {
        "status":          cache["status"],
        "parse_timestamp": json_data.get("parse_timestamp"),
        "raw_file":        json_data.get("raw_file"),
        "total_raw_lines": json_data.get("total_raw_lines"),
        "parsed_count":    json_data.get("parsed_count"),
        "skipped_count":   json_data.get("skipped_count"),
        "data":            json_data.get("threats", []),
    }


@app.get("/api/v1/stats", tags=["data"])
async def get_stats(db: Session = Depends(get_db)):
    """Aggregate stats from SQLite (falls back to JSON)."""
    stats = crud.get_stats(db)
    if stats["total_threats"] > 0:
        return {
            "total_threats":   stats["total_threats"],
            "severities":      stats["severities"],
            "sources":         stats["sources"],
            "threat_types":    stats["threat_types"],
            "parse_timestamp": cache.get("last_run", ""),
        }

    # Fallback
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


@app.get("/api/v1/raw", tags=["data"])
async def get_raw_log():
    """Return the raw log file as plain text."""
    if not os.path.exists(RAW_LOG_PATH):
        return {"error": "raw_logs.txt not found. Run /api/v1/update first."}
    with open(RAW_LOG_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    return {"content": content, "lines": len(content.splitlines())}


# ── New Endpoints (Phases 3–8) ────────────────────────────────────────────────

@app.post("/api/v1/search", tags=["advanced"])
async def semantic_search(
    q: str = Query(..., description="Free-text query to search logs semantically"),
    top_k: int = Query(10, ge=1, le=50),
):
    """
    Phase 3: Semantic search using sentence-transformer embeddings.
    Returns top-k most similar log records.
    """
    try:
        from services.embedder import search_similar
        results = search_similar(q, top_k=top_k)
        return {"query": q, "count": len(results), "results": results}
    except ImportError as e:
        return {"error": str(e), "hint": "Install sentence-transformers: pip install sentence-transformers"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/graph", tags=["advanced"])
async def get_graph(db: Session = Depends(get_db)):
    """
    Phase 4: NetworkX threat graph.
    Returns nodes (IPs + threat types) and edges (ATTACKS / RELATED_TO).
    """
    try:
        from services.graph_builder import get_graph, graph_to_json
        entries = crud.get_all_logs(db, limit=500)
        logs    = [e.to_dict() for e in entries] if entries else []

        if not logs:
            data = _load_normalized()
            logs = data.get("threats", []) if data else []

        G = get_graph(logs, force_rebuild=True)
        if G is None:
            return {"error": "No data available to build graph. Fetch data first."}

        return graph_to_json(G)
    except ImportError as e:
        return {"error": str(e), "hint": "Install networkx: pip install networkx"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/anomalies", tags=["advanced"])
async def get_anomalies(db: Session = Depends(get_db)):
    """
    Phase 5: GNN-based node anomaly scores.
    Runs GraphSAGE (or heuristic fallback) and returns scored nodes.
    """
    try:
        from services.gnn_model import run_anomaly_detection
        entries = crud.get_all_logs(db, limit=500)
        logs    = [e.to_dict() for e in entries] if entries else []

        if not logs:
            data = _load_normalized()
            logs = data.get("threats", []) if data else []

        scores = run_anomaly_detection(logs)
        sorted_nodes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return {
            "total_nodes":    len(scores),
            "anomalies":      [{"node": n, "score": s} for n, s in sorted_nodes],
            "high_risk_nodes": [{"node": n, "score": s} for n, s in sorted_nodes if s > 0.7],
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/v1/insights", tags=["advanced"])
async def get_insights(db: Session = Depends(get_db)):
    """
    Phase 8: Combined analysis — Hunter + Triager + Responder + SHAP.
    Returns actionable insights without any automated execution.
    """
    try:
        entries = crud.get_all_logs(db, limit=300)
        logs    = [e.to_dict() for e in entries] if entries else []

        if not logs:
            data = _load_normalized()
            logs = data.get("threats", []) if data else []

        if not logs:
            return {"error": "No data available. Run /api/v1/update first."}

        # 1. Triage
        from agents.triager import triage
        triage_result = triage(logs)

        # 2. Responder suggestions
        from agents.responder import generate_suggestions
        suggestions = generate_suggestions(triage_result)

        # 3. SHAP explanations on top escalations
        from services.explainer import explain_batch
        top_logs    = triage_result.get("escalate", [])[:10]
        explanations = explain_batch(top_logs)

        # 4. Hunter (best-effort — may fail if embeddings not ready)
        hunt_results = []
        try:
            from agents.hunter import hunt
            hunt_results = hunt(top_k=3)
        except Exception as he:
            hunt_results = [{"note": f"Hunter unavailable: {he}"}]

        return {
            "summary": {
                "total_logs":       len(logs),
                "escalate_count":   len(triage_result.get("escalate", [])),
                "monitor_count":    len(triage_result.get("monitor", [])),
                "flag_count":       len(triage_result.get("flag", [])),
            },
            "triage":        triage_result,
            "suggestions":   suggestions[:20],
            "explanations":  explanations,
            "hunt_results":  hunt_results,
        }
    except Exception as e:
        logger.error(f"Insights error: {e}")
        return {"error": str(e)}
