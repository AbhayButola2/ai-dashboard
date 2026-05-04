"""
services/graph_builder.py
--------------------------
Phase 4: NetworkX graph layer.

Nodes: IP addresses, Threat Types
Edges: source_ip →[ATTACKS]→ dest_ip
       source_ip →[RELATED_TO]→ threat_type

The graph is cached in memory and optionally persisted as a pickle.
"""
import os
import pickle
import logging
from typing import Dict, Any

logger = logging.getLogger("graph_builder")

_graph_cache = None
GRAPH_PICKLE = os.path.join(os.path.dirname(__file__), "..", "graph.pkl")


def build_graph(logs: list):
    """Build a NetworkX DiGraph from a list of log dicts."""
    try:
        import networkx as nx
    except ImportError:
        raise ImportError("networkx not installed. Run: pip install networkx")

    G = nx.DiGraph()

    # Track node metadata
    ip_freq: Dict[str, int] = {}
    ip_severity: Dict[str, float] = {}
    severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    for log in logs:
        src = log.get("ioc") or log.get("source_ip") or ""
        dst = log.get("dst_ip") or log.get("destination_ip") or ""
        tt  = log.get("threat_type", "unknown")
        sev = log.get("severity", "Unknown")
        sev_score = severity_map.get(sev, 0)

        if not src:
            continue

        # Update frequency/severity
        ip_freq[src] = ip_freq.get(src, 0) + 1
        ip_severity[src] = max(ip_severity.get(src, 0), sev_score)

        # Add IP node
        if not G.has_node(src):
            G.add_node(src, node_type="ip", frequency=0, max_severity=0)
        G.nodes[src]["frequency"] = ip_freq[src]
        G.nodes[src]["max_severity"] = ip_severity[src]

        # Add Threat Type node
        tt_node = f"threat:{tt}"
        if not G.has_node(tt_node):
            G.add_node(tt_node, node_type="threat_type", label=tt)

        # Edges
        if dst:
            if not G.has_node(dst):
                G.add_node(dst, node_type="ip", frequency=0, max_severity=0)
            if G.has_edge(src, dst):
                G[src][dst]["weight"] += 1
            else:
                G.add_edge(src, dst, relation="ATTACKS", weight=1)

        # IP → ThreatType
        if G.has_edge(src, tt_node):
            G[src][tt_node]["weight"] += 1
        else:
            G.add_edge(src, tt_node, relation="RELATED_TO", weight=1)

    return G


def get_graph(logs: list = None, force_rebuild: bool = False):
    """Return cached graph or build a new one. Persists to disk."""
    global _graph_cache

    if _graph_cache is not None and not force_rebuild and logs is None:
        return _graph_cache

    if logs is not None:
        _graph_cache = build_graph(logs)
        # Persist
        try:
            with open(GRAPH_PICKLE, "wb") as f:
                pickle.dump(_graph_cache, f)
        except Exception as e:
            logger.warning(f"Could not pickle graph: {e}")
        return _graph_cache

    # Try loading from disk
    if os.path.exists(GRAPH_PICKLE):
        try:
            with open(GRAPH_PICKLE, "rb") as f:
                _graph_cache = pickle.load(f)
            logger.info("Graph loaded from disk.")
            return _graph_cache
        except Exception:
            pass

    return None


def graph_to_json(G) -> dict:
    """Serialize NetworkX DiGraph to {nodes, edges} JSON-friendly format."""
    import networkx as nx
    nodes = []
    for node_id, data in G.nodes(data=True):
        nodes.append({
            "id":          node_id,
            "node_type":   data.get("node_type", "unknown"),
            "label":       data.get("label", node_id),
            "frequency":   data.get("frequency", 0),
            "max_severity": data.get("max_severity", 0),
            "anomaly_score": data.get("anomaly_score", 0.0),
        })

    edges = []
    for src, dst, data in G.edges(data=True):
        edges.append({
            "source":   src,
            "target":   dst,
            "relation": data.get("relation", ""),
            "weight":   data.get("weight", 1),
        })

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes":      nodes,
        "edges":      edges,
    }
