import json
import pandas as pd
import streamlit as st

st.set_page_config(page_title="CyberShield AI Dashboard", page_icon="🛡️", layout="wide")

def load_report():
    with open("reports/incidents.json", "r") as file:
        return json.load(file)

report = load_report()
summary = report["summary"]
incidents = report["incidents"]

st.title(" CyberShield AI Dashboard")
st.write("AWS Cloud Security Monitoring & AI Incident Analysis")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Incidents", summary["totalIncidents"])
col2.metric("Critical", summary["criticalIncidents"])
col3.metric("High", summary["highIncidents"])
col4.metric("Avg Threat Score", f"{summary['averageThreatScore']}/100")

st.subheader(" Recent Security Incidents")

df = pd.DataFrame(incidents)
st.dataframe(df, use_container_width=True)

st.subheader(" AI Recommendation")

st.info(
    "Critical logging events such as DeleteTrail or StopLogging may indicate an attacker "
    "trying to hide malicious activity. Review IAM users, preserve logs, and investigate source IPs."
)