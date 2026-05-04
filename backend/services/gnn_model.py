"""
services/gnn_model.py
----------------------
Phase 5: GraphSAGE node anomaly scoring using PyTorch Geometric.

Architecture:
  - 2× GraphSAGE layers
  - ReLU activations
  - Output: 32-dim embedding per node
  - Anomaly score = reconstruction error (distance from mean embedding)

The model runs in batch/offline mode and writes scores back to the graph
and to the SQLite DB.
"""
import logging
import os
import json
import numpy as np
from typing import Dict

logger = logging.getLogger("gnn_model")

_TORCH_AVAILABLE = False
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _TORCH_AVAILABLE = True
except ImportError:
    pass

_PYG_AVAILABLE = False
try:
    from torch_geometric.nn import SAGEConv
    from torch_geometric.data import Data
    _PYG_AVAILABLE = True
except ImportError:
    pass


class GraphSAGEAnomalyModel(nn.Module):
    def __init__(self, in_channels: int, hidden: int = 64, out: int = 32):
        super().__init__()
        if not _PYG_AVAILABLE:
            raise ImportError("torch_geometric not installed.")
        self.conv1 = SAGEConv(in_channels, hidden)
        self.conv2 = SAGEConv(hidden, out)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = self.conv2(x, edge_index)
        return x  # (N, out)


def _build_pyg_data(G):
    """Convert NetworkX graph to PyG Data object with node features."""
    import torch
    node_list = list(G.nodes())
    node_idx  = {n: i for i, n in enumerate(node_list)}

    features = []
    for node in node_list:
        d = G.nodes[node]
        freq   = float(d.get("frequency", 0))
        sev    = float(d.get("max_severity", 0))
        degree = float(G.degree(node))
        features.append([freq, sev, degree])

    x = torch.tensor(features, dtype=torch.float)

    edge_src, edge_dst = [], []
    for u, v in G.edges():
        if u in node_idx and v in node_idx:
            edge_src.append(node_idx[u])
            edge_dst.append(node_idx[v])

    if edge_src:
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    return Data(x=x, edge_index=edge_index), node_list


def compute_anomaly_scores(G) -> Dict[str, float]:
    """
    Run GraphSAGE on G, compute anomaly scores per node.
    Returns dict: node_id → anomaly_score (float, higher = more anomalous).
    Falls back to a heuristic if PyG/Torch not available.
    """
    if not _TORCH_AVAILABLE or not _PYG_AVAILABLE:
        logger.warning("PyTorch/PyG not available — using heuristic anomaly scores.")
        return _heuristic_anomaly(G)

    try:
        data, node_list = _build_pyg_data(G)
        in_ch = data.x.shape[1]
        model = GraphSAGEAnomalyModel(in_channels=in_ch)
        model.eval()

        with torch.no_grad():
            embeddings = model(data.x, data.edge_index).numpy()  # (N, 32)

        # Anomaly score = distance from centroid
        centroid = embeddings.mean(axis=0)
        scores   = np.linalg.norm(embeddings - centroid, axis=1)

        # Normalize to [0, 1]
        max_s = scores.max() + 1e-10
        scores = scores / max_s

        return {node: float(scores[i]) for i, node in enumerate(node_list)}

    except Exception as e:
        logger.error(f"GNN scoring failed: {e} — falling back to heuristic.")
        return _heuristic_anomaly(G)


def _heuristic_anomaly(G) -> Dict[str, float]:
    """Fallback: score based on degree + severity."""
    scores = {}
    max_degree = max((G.degree(n) for n in G.nodes()), default=1)
    for node in G.nodes():
        d = G.nodes[node]
        freq   = d.get("frequency", 0) / max(1, max_degree)
        sev    = d.get("max_severity", 0) / 4.0
        degree = G.degree(node) / max(1, max_degree)
        scores[node] = round(min(1.0, 0.4 * freq + 0.4 * sev + 0.2 * degree), 4)
    return scores


def run_anomaly_detection(logs: list) -> Dict[str, float]:
    """
    High-level entry: build graph → run GNN → update DB + graph.
    Returns node anomaly score dict.
    """
    from services.graph_builder import get_graph
    from db.database import SessionLocal
    from db.crud import update_anomaly_score

    G = get_graph(logs, force_rebuild=True)
    if G is None or G.number_of_nodes() == 0:
        return {}

    scores = compute_anomaly_scores(G)

    # Attach scores to graph nodes
    for node, score in scores.items():
        if G.has_node(node):
            G.nodes[node]["anomaly_score"] = score

    # Persist to DB for IP nodes (match by source_ip)
    db = SessionLocal()
    try:
        from db.models import LogEntry
        from sqlalchemy import func as sqlfunc
        for node, score in scores.items():
            entries = db.query(LogEntry).filter(LogEntry.source_ip == node).all()
            for e in entries:
                e.anomaly_score = score
        db.commit()
    except Exception as e:
        logger.error(f"DB anomaly score update failed: {e}")
    finally:
        db.close()

    logger.info(f"Anomaly scores computed for {len(scores)} nodes.")
    return scores
