"""
ingestion_worker.py
-------------------
Phase 2: Queue-based log ingestion worker.

Replaces FastAPI BackgroundTasks with a proper threading.Thread + queue.Queue
so logs are processed sequentially with no data loss.

Usage:
    from ingestion_worker import ingestion_queue, start_worker
    start_worker()          # call once at app startup
    ingestion_queue.put({"records": [...], "meta": {...}})   # enqueue work
"""
import queue
import threading
import logging
import json
import os

logger = logging.getLogger("ingestion_worker")

# Global queue — any part of the app can enqueue jobs
ingestion_queue: queue.Queue = queue.Queue()

ROOT = os.path.dirname(__file__)
NORM_LOG_PATH = os.path.join(ROOT, "normalized_logs.json")

_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _worker_loop():
    """Background thread: drains ingestion_queue and persists each batch."""
    from db.database import SessionLocal
    from db.crud import bulk_upsert
    from services.embedder import embed_and_store  # lazy import — heavy model

    logger.info("Ingestion worker started.")
    while not _stop_event.is_set():
        try:
            job = ingestion_queue.get(timeout=2)  # blocks up to 2 s
        except queue.Empty:
            continue

        try:
            records = job.get("records", [])
            meta    = job.get("meta", {})
            logger.info(f"Processing batch of {len(records)} records …")

            # 1. Persist to SQLite
            db = SessionLocal()
            try:
                inserted = bulk_upsert(db, records)
                logger.info(f"  → {inserted} records upserted to DB")
            finally:
                db.close()

            # 2. Keep JSON backup for legacy compatibility
            payload = {**meta, "threats": records}
            with open(NORM_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)

            # 3. Generate embeddings for this batch (non-blocking — errors are soft)
            try:
                embed_and_store(records)
            except Exception as emb_err:
                logger.warning(f"  Embedding step skipped: {emb_err}")

        except Exception as e:
            logger.error(f"Worker error on job: {e}")
        finally:
            ingestion_queue.task_done()

    logger.info("Ingestion worker stopped.")


def start_worker():
    """Start the background daemon thread (idempotent)."""
    global _worker_thread
    if _worker_thread and _worker_thread.is_alive():
        return
    _stop_event.clear()
    _worker_thread = threading.Thread(target=_worker_loop, daemon=True, name="ingestion-worker")
    _worker_thread.start()
    logger.info("Ingestion worker thread launched.")


def stop_worker():
    """Gracefully stop the worker (used in tests / shutdown)."""
    _stop_event.set()
    if _worker_thread:
        _worker_thread.join(timeout=5)
