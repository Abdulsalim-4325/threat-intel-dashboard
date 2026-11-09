import streamlit as st
import requests
import pandas as pd

# Connect directly to your live Render backend
API_BASE_URL = "https://threat-intel-api-u5pa.onrender.com/api/v1"
BACKEND_ROOT = "https://threat-intel-api-u5pa.onrender.com"

st.set_page_config(
    page_title="V.A.L.A.R. Threat Intel",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Automated Threat Intelligence Aggregator")
st.markdown("### STIX 2.1 OSINT Normalization Engine")
st.divider()

# Check system health from live backend
@st.cache_data(ttl=30)
def check_health():
    try:
        res = requests.get(f"{BACKEND_ROOT}/")
        return res.status_code == 200
    except:
        return False

# Fetch STIX Bundle or indicators from live backend
@st.cache_data(ttl=30)
def fetch_indicators():
    try:
        res = requests.get(f"{API_BASE_URL}/bundle")
        if res.status_code == 200:
            return res.json()
        return None
    except:
        return None

is_online = check_health()
data = fetch_indicators()

col1, col2, col3 = st.columns(3)
col1.metric("Cloud Backend Status", "🟢 ONLINE (Render)" if is_online else "🔴 OFFLINE")

if data and "objects" in data:
    objects = data["objects"]
    indicators = [obj for obj in objects if obj.get("type") == "indicator"]
    malware = [obj for obj in objects if obj.get("type") == "malware"]
    
    col2.metric("Active STIX Indicators", len(indicators))
    col3.metric("Malware Signatures", len(malware))
    
    st.divider()
    st.subheader("📡 Live Indicators of Compromise (IOCs)")
    
    table_data = []
    for ioc in indicators:
        table_data.append({
            "Created": ioc.get("created", "N/A"),
            "Name": ioc.get("name", "Threat Indicator"),
            "Pattern": ioc.get("pattern", "N/A"),
            "Valid From": ioc.get("valid_from", "N/A")
        })
    
    if table_data:
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Backend is live, but current STIX bundle is empty. Trigger an ingestion via the API!")
else:
    col2.metric("Active STIX Indicators", 0)
    col3.metric("Malware Signatures", 0)
    st.warning("Connected to Render backend, awaiting initial OSINT ingestion payload.")