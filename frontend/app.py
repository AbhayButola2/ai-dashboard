"""
frontend/app.py — Assisted SOC Dashboard  v3.0
===============================================
Extended Streamlit UI for the upgraded backend.

New tabs:
  • Overview   — existing KPIs + charts
  • Threat Graph — NetworkX 2D visualization
  • Anomaly Radar — GNN-scored nodes
  • Semantic Search — free-text log search
  • SOC Insights — triage + responder + SHAP
"""

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json

st.set_page_config(
    page_title="AI Threat Intelligence SOC",
    layout="wide",
    initial_sidebar_state="expanded",
    page_icon="🛡️",
)

# ── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
  html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
  .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }
  h1, h2, h3 { font-weight: 600; }
  .stMetric { background: rgba(255,255,255,0.04); border-radius: 10px; padding: 12px; }
  .priority-ESCALATE { color: #ff4d4d; font-weight: 700; }
  .priority-MONITOR  { color: #ffa94d; font-weight: 600; }
  .priority-FLAG     { color: #ffe066; font-weight: 600; }
  .priority-NORMAL   { color: #69db7c; }
  .stTabs [data-baseweb="tab"] { font-size: 0.95rem; font-weight: 500; }
</style>
""", unsafe_allow_html=True)

API = "http://localhost:8000/api/v1"

# ── Helpers ───────────────────────────────────────────────────────────────────

@st.cache_data(ttl=10, show_spinner=False)
def fetch_threats():
    try:
        r = requests.get(f"{API}/threats", timeout=30)
        if r.status_code == 200:
            d = r.json()
            return pd.DataFrame(d.get("data", [])), d
    except Exception as e:
        st.error(f"Backend unreachable: {e}")
    return pd.DataFrame(), {}


@st.cache_data(ttl=30, show_spinner=False)
def fetch_graph():
    try:
        r = requests.get(f"{API}/graph", timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


@st.cache_data(ttl=60, show_spinner=False)
def fetch_anomalies():
    try:
        r = requests.get(f"{API}/anomalies", timeout=60)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


@st.cache_data(ttl=60, show_spinner=False)
def fetch_insights():
    try:
        r = requests.get(f"{API}/insights", timeout=60)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def do_search(query: str, top_k: int = 10):
    try:
        r = requests.post(f"{API}/search", params={"q": query, "top_k": top_k}, timeout=30)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        st.error(str(e))
    return {}


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("SOC Dashboard")
    st.caption("Assisted Threat Intelligence v3.0")
    st.divider()

    st.subheader("Data Controls")
    if st.button("🔄 Fetch Live Data", use_container_width=True):
        with st.spinner("Triggering pipeline …"):
            try:
                requests.get(f"{API}/update", timeout=60)
                st.cache_data.clear()
                st.success("Pipeline triggered. Refresh in a moment.")
            except Exception as e:
                st.error(str(e))

    st.divider()
    st.subheader("Upload Log File")
    uploaded = st.file_uploader("Drag & drop log file", type=["txt", "log", "json", "csv"])
    if uploaded and st.button("⬆️ Process File", use_container_width=True):
        with st.spinner("Processing …"):
            try:
                files = {"file": (uploaded.name, uploaded.getvalue(), "multipart/form-data")}
                res = requests.post(f"{API}/upload", files=files, timeout=60)
                if res.status_code == 200:
                    j = res.json()
                    if "error" in j:
                        st.error(j["error"])
                    else:
                        st.success(f"Parsed {j.get('parsed_count', 0)} records.")
                        st.cache_data.clear()
                        st.rerun()
                else:
                    st.error("Upload failed.")
            except Exception as e:
                st.error(str(e))

    st.divider()
    if st.button("🗑️ Clear Cache", use_container_width=True):
        st.cache_data.clear()
        st.rerun()


# ── Main content ──────────────────────────────────────────────────────────────
st.markdown("## 🛡️ AI-Assisted SOC — Threat Intelligence Dashboard")

df, meta = fetch_threats()

# KPI Row
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Records",   len(df) if not df.empty else 0)
col2.metric("Critical",
            int((df["severity"] == "Critical").sum()) if "severity" in df.columns else 0)
col3.metric("High",
            int((df["severity"] == "High").sum()) if "severity" in df.columns else 0)
col4.metric("Sources",
            df["source"].nunique() if "source" in df.columns else 0)
col5.metric("Avg Confidence",
            f"{int(df['confidence'].mean())}%" if "confidence" in df.columns and not df.empty else "—")

st.write("")

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🕸️ Threat Graph",
    "🚨 Anomaly Radar",
    "🔍 Semantic Search",
    "🤖 SOC Insights",
])


# ─── Tab 1: Overview ─────────────────────────────────────────────────────────
with tab1:
    if df.empty:
        st.info("No data available. Fetch live data or upload a log file from the sidebar.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            if "severity" in df.columns:
                fig = px.pie(df, names="severity", title="Severity Distribution",
                             hole=0.45,
                             color_discrete_sequence=["#ff4d4d","#ffa94d","#ffe066","#69db7c","#a9e34b"])
                fig.update_layout(margin=dict(t=40,b=0,l=0,r=0), paper_bgcolor="rgba(0,0,0,0)", font_color="#eee")
                st.plotly_chart(fig, use_container_width=True)
        with c2:
            if "source" in df.columns:
                fig2 = px.bar(df, x="source", title="Volume by Source",
                              color="source", color_discrete_sequence=px.colors.qualitative.Pastel)
                fig2.update_layout(margin=dict(t=40,b=0,l=0,r=0),
                                   paper_bgcolor="rgba(0,0,0,0)", font_color="#eee", showlegend=False)
                st.plotly_chart(fig2, use_container_width=True)

        if "threat_type" in df.columns:
            tt_counts = df["threat_type"].value_counts().head(10)
            fig3 = px.bar(tt_counts, orientation="h", title="Top 10 Threat Types",
                          color=tt_counts.values, color_continuous_scale="Reds")
            fig3.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#eee",
                               yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig3, use_container_width=True)

        st.subheader("Processed Threat Feed")
        cols_show = [c for c in ["timestamp","source","threat_type","severity","ioc","tags","raw_line"] if c in df.columns]
        disp = df[cols_show].copy()
        if "severity" in disp.columns:
            order_map = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
            disp["_sort"] = disp["severity"].map(order_map).fillna(5)
            disp = disp.sort_values("_sort").drop(columns=["_sort"])
        st.dataframe(disp.head(150), use_container_width=True, hide_index=True)


# ─── Tab 2: Threat Graph ─────────────────────────────────────────────────────
with tab2:
    st.subheader("🕸️ Threat Relationship Graph")
    st.caption("Nodes: IP addresses + Threat types · Edges: ATTACKS / RELATED_TO")

    if st.button("🔃 Rebuild Graph", key="rebuild_graph"):
        st.cache_data.clear()

    g_data = fetch_graph()

    if not g_data or "error" in g_data:
        err = g_data.get("error", "No graph data.") if g_data else "No graph data."
        st.warning(f"{err} — Fetch live data first.")
    else:
        nodes = g_data.get("nodes", [])
        edges = g_data.get("edges", [])
        st.metric("Nodes", g_data.get("node_count", 0), delta=None)
        col_g1, col_g2 = st.columns([3,1])

        with col_g1:
            # Build a Plotly scatter network
            import random, math
            random.seed(42)
            n = len(nodes)
            pos = {}
            for i, node in enumerate(nodes):
                angle = 2 * math.pi * i / max(n, 1)
                r = 1 if node["node_type"] == "threat_type" else random.uniform(0.3, 0.9)
                pos[node["id"]] = (r * math.cos(angle), r * math.sin(angle))

            edge_x, edge_y = [], []
            for e in edges:
                x0, y0 = pos.get(e["source"], (0, 0))
                x1, y1 = pos.get(e["target"], (0, 0))
                edge_x += [x0, x1, None]
                edge_y += [y0, y1, None]

            node_x = [pos.get(nd["id"], (0,0))[0] for nd in nodes]
            node_y = [pos.get(nd["id"], (0,0))[1] for nd in nodes]
            node_colors = [
                "#ff4d4d" if nd["node_type"] == "threat_type" else
                ("#ffa94d" if nd.get("max_severity", 0) >= 3 else "#69db7c")
                for nd in nodes
            ]
            node_text = [f"{nd['id']}<br>Type: {nd['node_type']}<br>Freq: {nd.get('frequency',0)}" for nd in nodes]

            fig_g = go.Figure()
            fig_g.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
                                        line=dict(width=0.6, color="#555"), hoverinfo="none"))
            fig_g.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text",
                                        marker=dict(size=10, color=node_colors, line=dict(width=1, color="#222")),
                                        text=[nd["id"][:15] for nd in nodes],
                                        textposition="top center",
                                        hovertext=node_text, hoverinfo="text"))
            fig_g.update_layout(
                showlegend=False, hovermode="closest",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=500, margin=dict(t=20, b=20, l=20, r=20),
                font=dict(color="#eee"),
            )
            st.plotly_chart(fig_g, use_container_width=True)

        with col_g2:
            st.markdown("**Legend**")
            st.markdown("🔴 Threat Type node")
            st.markdown("🟠 High-severity IP")
            st.markdown("🟢 Normal IP")
            st.markdown(f"**{len(edges)}** edges total")
            st.divider()
            st.markdown("**Top IPs by frequency**")
            ip_nodes = [nd for nd in nodes if nd["node_type"] == "ip"]
            ip_nodes.sort(key=lambda x: x.get("frequency", 0), reverse=True)
            for nd in ip_nodes[:10]:
                st.markdown(f"`{nd['id']}` — {nd.get('frequency',0)}×")


# ─── Tab 3: Anomaly Radar ────────────────────────────────────────────────────
with tab3:
    st.subheader("🚨 GNN Anomaly Radar")
    st.caption("GraphSAGE node anomaly scores — score >0.7 = high risk")

    if st.button("⚡ Compute Anomalies", key="compute_anomalies"):
        st.cache_data.clear()

    anom_data = fetch_anomalies()

    if not anom_data or "error" in anom_data:
        st.warning(anom_data.get("error", "No anomaly data.") if anom_data else "No anomaly data. Fetch data first.")
    else:
        high_risk = anom_data.get("high_risk_nodes", [])
        all_nodes = anom_data.get("anomalies", [])

        m1, m2 = st.columns(2)
        m1.metric("Total Nodes Scored", anom_data.get("total_nodes", 0))
        m2.metric("High-Risk Nodes (>0.7)", len(high_risk))

        if high_risk:
            st.error(f"⚠️ {len(high_risk)} high-risk node(s) detected!")
            hr_df = pd.DataFrame(high_risk)
            st.dataframe(hr_df, use_container_width=True, hide_index=True)

        st.divider()
        if all_nodes:
            anom_df = pd.DataFrame(all_nodes[:50])
            fig_anom = px.bar(anom_df, x="node", y="score", title="Node Anomaly Scores (top 50)",
                              color="score", color_continuous_scale="Reds")
            fig_anom.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#eee",
                                    xaxis_tickangle=-45)
            st.plotly_chart(fig_anom, use_container_width=True)


# ─── Tab 4: Semantic Search ──────────────────────────────────────────────────
with tab4:
    st.subheader("🔍 Semantic Log Search")
    st.caption("Uses all-MiniLM-L6-v2 embeddings for similarity-based search")

    query = st.text_input("Enter your search query:", placeholder="e.g. botnet C2 server traffic")
    top_k = st.slider("Number of results", 3, 30, 10)

    if st.button("🔎 Search", key="do_search") and query:
        with st.spinner("Searching …"):
            result = do_search(query, top_k)

        if "error" in result:
            st.error(result["error"])
            if "hint" in result:
                st.info(result["hint"])
        elif result.get("results"):
            st.success(f"Found {result['count']} similar records.")
            res_df = pd.DataFrame(result["results"])
            cols   = [c for c in ["similarity_score","source","threat_type","severity","ioc","tags","raw_line"] if c in res_df.columns]
            st.dataframe(res_df[cols], use_container_width=True, hide_index=True)
        else:
            st.info("No results. Make sure embeddings have been generated (fetch data first).")


# ─── Tab 5: SOC Insights ─────────────────────────────────────────────────────
with tab5:
    st.subheader("🤖 SOC Insights — Assisted Analysis")
    st.caption("Rule-based triage + SHAP explainability + Threat Hunter")
    st.info("ℹ️ All suggestions are **advisory only**. No automated actions are taken.", icon="🛡️")

    if st.button("🧠 Run Full Analysis", key="run_insights", use_container_width=True):
        st.cache_data.clear()

    insights = fetch_insights()

    if not insights or "error" in insights:
        st.warning(insights.get("error", "No insights available.") if insights else "Fetch data first.")
    else:
        summary = insights.get("summary", {})
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("Total Logs",    summary.get("total_logs", 0))
        s2.metric("🔴 Escalate",   summary.get("escalate_count", 0))
        s3.metric("🟠 Monitor",    summary.get("monitor_count", 0))
        s4.metric("🟡 Flag",       summary.get("flag_count", 0))

        # Suggestions
        suggestions = insights.get("suggestions", [])
        if suggestions:
            st.subheader("📋 Recommended Actions")
            for sug in suggestions[:15]:
                priority = sug.get("priority", "NORMAL")
                color    = {"ESCALATE":"🔴","FLAG":"🟡","MONITOR":"🟠","NORMAL":"🟢"}.get(priority,"⚪")
                with st.expander(f"{color} [{priority}] {sug.get('source_ip','?')} — {sug.get('threat_type','?')} ({sug.get('severity','?')})"):
                    for action in sug.get("suggested_actions", []):
                        st.markdown(f"  - {action}")
                    st.caption(sug.get("⚠️_note", ""))

        st.divider()

        # SHAP Explanations
        explanations = insights.get("explanations", [])
        if explanations:
            st.subheader("🔬 SHAP Explanations (Top Escalations)")
            exp_df_rows = []
            for exp in explanations:
                exp_df_rows.append({
                    "Log ID":    exp.get("log_id", ""),
                    "Predicted": exp.get("predicted_severity", ""),
                    "Explanation": exp.get("explanation", ""),
                    "threat_type_enc": exp.get("feature_importances", {}).get("threat_type_enc", 0),
                    "tags_count":      exp.get("feature_importances", {}).get("tags_count", 0),
                    "source_enc":      exp.get("feature_importances", {}).get("source_enc", 0),
                })
            exp_df = pd.DataFrame(exp_df_rows)
            st.dataframe(exp_df, use_container_width=True, hide_index=True)

        # Hunt results
        hunt = insights.get("hunt_results", [])
        if hunt and isinstance(hunt[0], dict) and "signature" in hunt[0]:
            st.subheader("🎯 Threat Hunter Results")
            for h in hunt[:6]:
                sig  = h.get("signature", "")
                sims = h.get("max_similarity", 0)
                with st.expander(f"Signature: '{sig}' — max similarity: {sims:.3f}"):
                    for match in h.get("matched_logs", [])[:3]:
                        st.markdown(
                            f"- `{match.get('ioc','?')}` · {match.get('threat_type','?')} "
                            f"· **{match.get('severity','?')}** · sim={match.get('similarity_score',0):.3f}"
                        )
