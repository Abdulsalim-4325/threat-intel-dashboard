import streamlit as st
import requests
import pandas as pd
from datetime import datetime

# Connect to your live Render backend
API_BASE_URL = "https://threat-intel-api-u5pa.onrender.com/api/v1"

st.set_page_config(
    page_title="V.A.L.A.R. Threat Intel",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Automated Threat Intelligence Aggregator")
st.markdown("### STIX 2.1 OSINT Normalization Engine")
st.divider()

# --- FETCH DATA ---
@st.cache_data(ttl=60)
def fetch_system_health():
    try:
        response = requests.get(f"https://threat-intel-api-u5pa.onrender.com/")
        return response.status_code == 200
    except:
        return False

@st.cache_data(ttl=60)
def fetch_stix_bundle():
    try:
        # Assuming your bundle endpoint is at /api/v1/bundle
        response = requests.get(f"{API_BASE_URL}/bundle")
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

# --- RENDER METRICS ---
is_online = fetch_system_health()
stix_data = fetch_stix_bundle()

col1, col2, col3 = st.columns(3)
col1.metric("Engine Status", "🟢 ONLINE" if is_online else "🔴 OFFLINE")

if stix_data and "objects" in stix_data:
    objects = stix_data["objects"]
    indicators = [obj for obj in objects if obj.get("type") == "indicator"]
    malware = [obj for obj in objects if obj.get("type") == "malware"]
    
    col2.metric("Active IOCs (Indicators)", len(indicators))
    col3.metric("Known Malware Signatures", len(malware))
    
    st.divider()
    st.subheader("📡 Latest Ingested Indicators of Compromise (IOCs)")
    
    # Flatten the STIX data for the data table
    table_data = []
    for ioc in indicators:
        table_data.append({
            "Created": ioc.get("created", ""),
            "Name": ioc.get("name", "Unnamed IOC"),
            "Pattern": ioc.get("pattern", ""),
            "Valid From": ioc.get("valid_from", "")
        })
    
    if table_data:
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No indicators found in the current STIX bundle.")
else:
    col2.metric("Active IOCs (Indicators)", 0)
    col3.metric("Known Malware Signatures", 0)
    st.warning("Awaiting STIX 2.1 data ingestion from backend...")