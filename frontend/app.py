import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Threat Intel", layout="wide", initial_sidebar_state="expanded")

# Minimal modern styling
st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    h1, h2, h3 { font-family: sans-serif; font-weight: 500; }
</style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:8000/api/v1"

@st.cache_data(ttl=5, show_spinner=False)
def fetch_threat_data():
    try:
        r = requests.get(f"{API_URL}/threats", timeout=45)
        if r.status_code == 200:
            data = r.json()
            if data.get("data"):
                return pd.DataFrame(data["data"]), data
    except Exception as e:
        st.error(f"Error fetching data: {e}")
    return pd.DataFrame(), {}

def trigger_update():
    try:
        requests.get(f"{API_URL}/update", timeout=45)
        st.cache_data.clear()
        st.success("Auto-fetch completed. Processing in background...")
    except Exception as e:
        st.error(f"Backend update error: {e}")

st.title("Threat Intelligence Dashboard")
st.caption("AI-driven visualization of normalized security logs")

# --- Sidebar Controls ---
with st.sidebar:
    st.header("Data Source")
    st.write("Upload arbitrary system logs, server logs, or JSON files. They will be parsed and visualized entirely on the backend.")
    uploaded_file = st.file_uploader("Upload Log File", type=["txt", "log", "json", "csv"])
    
    if uploaded_file is not None:
        if st.button("Process Uploaded File"):
            with st.spinner("Uploading and parsing..."):
                try:
                    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "multipart/form-data")}
                    response = requests.post(f"{API_URL}/upload", files=files)
                    if response.status_code == 200:
                        res_json = response.json()
                        if "error" in res_json:
                            st.error(res_json["error"])
                        else:
                            st.success(f"Parsed {res_json.get('parsed_count', 0)} records.")
                            st.cache_data.clear()
                            st.rerun()
                    else:
                        st.error("Upload failed.")
                except Exception as e:
                    st.error(f"Error: {e}")
                    
    st.divider()
    st.write("Or use the default live feed:")
    if st.button("Fetch Live Public Data"):
        trigger_update()

# --- Main Dashboard ---
df, meta = fetch_threat_data()

if df.empty:
    st.info("No data available. Please upload a log file or fetch live data from the sidebar.")
else:
    # Top KPI metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Records", len(df))
    m2.metric("Critical Alerts", len(df[df["severity"] == "Critical"]) if "severity" in df.columns else 0)
    m3.metric("Data Sources", df["source"].nunique() if "source" in df.columns else 0)
    avg_conf = int(df["confidence"].mean()) if "confidence" in df.columns else 0
    m4.metric("Average Confidence", f"{avg_conf}%")

    st.write("")

    # Interactive Plotly Charts
    c1, c2 = st.columns(2)

    with c1:
        if "severity" in df.columns:
            fig_sev = px.pie(
                df, names="severity", title="Alert Severity Distribution",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.RdBu_r
            )
            fig_sev.update_layout(margin=dict(t=40, b=0, l=0, r=0))
            st.plotly_chart(fig_sev, use_container_width=True)

    with c2:
        if "source" in df.columns:
            fig_src = px.bar(
                df, x="source", title="Data Source Volume",
                color="source",
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_src.update_layout(margin=dict(t=40, b=0, l=0, r=0), showlegend=False)
            st.plotly_chart(fig_src, use_container_width=True)

    st.subheader("Processed Threat Feed")
    # Show clean minimalist table highlighting the outcome of backend parsing
    cols_to_show = [c for c in ["timestamp", "source", "threat_type", "severity", "raw_line", "ioc"] if c in df.columns]
    display_df = df[cols_to_show].copy()
    
    if "severity" in display_df.columns:
        # Sort so criticals appear first
        sort_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
        display_df["sort_val"] = display_df["severity"].map(sort_order).fillna(5)
        display_df = display_df.sort_values("sort_val").drop(columns=["sort_val"])
        
    st.dataframe(display_df.head(100), use_container_width=True, hide_index=True)
