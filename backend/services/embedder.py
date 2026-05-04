"""
services/embedder.py
---------------------
Phase 3: Semantic embeddings using sentence-transformers (all-MiniLM-L6-v2).

- embed_text(text)          → np.ndarray
- embed_and_store(records)  → writes embeddings to SQLite
- search_similar(query, k)  → top-k log dicts by cosine similarity
"""
import json
import logging
import numpy as np
from typing import List

logger = logging.getLogger("embedder")

# Lazy-load model (heavy — ~90 MB)
_model = None

def _get_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("SentenceTransformer model loaded.")
        except ImportError:
            raise ImportError("sentence-transformers not installed. Run: pip install sentence-transformers")
    return _model


def _log_to_text(record: dict) -> str:
    """Convert a log record dict to a plain text representation for embedding."""
    parts = [
        record.get("threat_type", ""),
        record.get("severity", ""),
        record.get("source", ""),
        record.get("tags", ""),
        record.get("malware_alias", ""),
        record.get("ioc_type", ""),
        record.get("raw_line", "")[:200],  # truncate very long raw lines
    ]
    return " | ".join(str(p) for p in parts if p)


def embed_text(text: str) -> np.ndarray:
    """Embed a single text string."""
    return _get_model().encode(text, convert_to_numpy=True)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    a_norm = a / (np.linalg.norm(a) + 1e-10)
    b_norm = b / (np.linalg.norm(b) + 1e-10)
    return float(np.dot(a_norm, b_norm))


def embed_and_store(records: list):
    """
    Generate embeddings for a list of log records and persist to SQLite.
    Skips records that already have an embedding.
    """
    from db.database import SessionLocal
    from db.crud import get_log_by_id, update_embedding

    if not records:
        return

    texts = [_log_to_text(r) for r in records]
    model = _get_model()
    embeddings = model.encode(texts, batch_size=32, show_progress_bar=False)

    db = SessionLocal()
    try:
        for record, emb in zip(records, embeddings):
            log_id = record.get("id", "")
            if not log_id:
                continue
            entry = get_log_by_id(db, log_id)
            if entry and entry.embedding is None:
                update_embedding(db, log_id, emb.tolist())
    finally:
        db.close()

    logger.info(f"Stored embeddings for {len(records)} records.")


def search_similar(query: str, top_k: int = 10) -> List[dict]:
    """
    Semantic search: find top-k logs most similar to the query string.
    Returns list of log dicts augmented with 'similarity_score'.
    """
    from db.database import SessionLocal
    from db.crud import get_logs_with_embeddings

    query_emb = embed_text(query)

    db = SessionLocal()
    try:
        entries = get_logs_with_embeddings(db)
    finally:
        db.close()

    if not entries:
        return []

    scored = []
    for entry in entries:
        try:
            emb = np.array(json.loads(entry.embedding), dtype=np.float32)
            sim = cosine_similarity(query_emb, emb)
            d = entry.to_dict()
            d["similarity_score"] = round(sim, 4)
            scored.append(d)
        except Exception:
            continue

    scored.sort(key=lambda x: x["similarity_score"], reverse=True)
    return scored[:top_k]
