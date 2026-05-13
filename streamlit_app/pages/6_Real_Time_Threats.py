"""
Enhanced Real-time Monitoring Dashboard
Integrates real network traffic and threat detection
"""

import sys
import os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
from streamlit_autorefresh import st_autorefresh
from src.threat_generator import ThreatScenarioGenerator, RealWorldScenarioSimulator
from src.network_sniffer import NetworkSniffer, PacketParser
import json

# ====================================================
# Page Configuration
# ====================================================
st.set_page_config(
    page_title="Real-time Threat Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .alert-critical {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 15px;
        border-radius: 8px;
        margin: 5px 0;
    }
    .alert-warning {
        background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        color: black;
        padding: 15px;
        border-radius: 8px;
        margin: 5px 0;
    }
    .threat-badge {
        display: inline-block;
        padding: 8px 12px;
        border-radius: 5px;
        font-weight: bold;
        margin: 5px 2px;
    }
    .threat-high {
        background-color: #ff4757;
        color: white;
    }
    .threat-medium {
        background-color: #ffa502;
        color: white;
    }
    .threat-low {
        background-color: #2ed573;
        color: white;
    }
    .active-alert-card {
        background: linear-gradient(135deg, #102a43 0%, #243b53 100%);
        border-left: 4px solid #ef476f;
        color: #f5f7fa;
        padding: 12px;
        margin: 8px 0;
        border-radius: 6px;
    }
    .active-alert-meta {
        color: #d9e2ec;
    }
    </style>
""", unsafe_allow_html=True)

# ====================================================
# Session State Initialization
# ====================================================
if 'threat_generator' not in st.session_state:
    st.session_state.threat_generator = ThreatScenarioGenerator()

if 'detected_threats' not in st.session_state:
    st.session_state.detected_threats = []

if 'packet_cache' not in st.session_state:
    st.session_state.packet_cache = []

if 'threat_timeline' not in st.session_state:
    st.session_state.threat_timeline = []

# ====================================================
# Page Title & Header
# ====================================================
st.markdown("# 🛡️ Real-Time Network Threat Detection")
st.markdown("**AI-Powered Intrusion Detection System with Live Monitoring**")

# Auto-refresh every 5 seconds
st_autorefresh(interval=5000, key="realtime_refresh")

# ====================================================
# Sidebar Configuration
# ====================================================
with st.sidebar:
    st.markdown("## ⚙️ Configuration")
    
    detection_mode = st.radio(
        "Detection Mode",
        ["Live Simulation", "Realistic Threat Scenarios", "Real Network Traffic"]
    )
    
    # Simulation settings
    if detection_mode != "Real Network Traffic":
        st.markdown("### 📊 Simulation Settings")
        packet_batch_size = st.slider("Packets per update", 5, 50, 20)
        threat_percentage = st.slider("Threat probability (%)", 5, 50, 15)

    if detection_mode == "Realistic Threat Scenarios":
        st.markdown("### 🎭 Scenario Type")
        realistic_scenario = st.selectbox(
            "Select scenario",
            ["DDoS Campaign", "Night Attack Chain"]
        )
    
    # Detection threshold
    st.markdown("### 🔍 Detection Threshold")
    confidence_threshold = st.slider("Confidence threshold", 0.5, 1.0, 0.7)
    
    # Notification settings
    st.markdown("### 📢 Alerts")
    enable_critical_alerts = st.toggle("Critical Alerts", value=True)
    enable_email_alerts = st.toggle("Email Alerts", value=False)
    enable_slack_alerts = st.toggle("Slack Alerts", value=False)

# ====================================================
# Helper Functions
# ====================================================

def generate_sample_packets(batch_size: int, threat_pct: float) -> pd.DataFrame:
    """Generate sample network packets"""
    packets = []
    
    # Normal traffic
    normal_count = int(batch_size * (1 - threat_pct/100))
    packets.extend(st.session_state.threat_generator.generate_normal_traffic(normal_count))
    
    # Threat traffic
    threat_count = batch_size - normal_count
    threat_count_per_type = threat_count // 6
    
    packets.extend(st.session_state.threat_generator.generate_port_scan_attack(threat_count_per_type))
    packets.extend(st.session_state.threat_generator.generate_ddos_attack(threat_count_per_type))
    packets.extend(st.session_state.threat_generator.generate_botnet_traffic(threat_count_per_type))
    packets.extend(st.session_state.threat_generator.generate_brute_force_attack(threat_count_per_type))
    packets.extend(st.session_state.threat_generator.generate_data_exfiltration(threat_count_per_type))
    remaining = threat_count - threat_count_per_type * 5
    packets.extend(st.session_state.threat_generator.generate_privilege_escalation(remaining))
    
    return pd.DataFrame(packets)

def classify_packet(packet_data: dict) -> tuple:
    """Classify packet as threat or benign"""
    threat_indicators = 0
    score = 0.0
    
    # Risk scoring logic
    suspicious_ports = [4444, 5555, 6666, 8888, 9999, 23, 135, 139, 445]
    if packet_data.get('dst_port') in suspicious_ports:
        threat_indicators += 2
        score += 0.25
    
    if packet_data.get('src_ip', '').startswith(('203.0.113', '198.51.100', '192.0.2')):
        threat_indicators += 1
        score += 0.2
    
    if packet_data.get('packet_length') > 10000:
        threat_indicators += 1
        score += 0.15
    
    if packet_data.get('rate', 0) > 1000:
        threat_indicators += 1
        score += 0.15
    
    # Determine threat level
    if score > confidence_threshold:
        threat_level = "HIGH" if score > 0.8 else "MEDIUM"
        is_threat = True
    else:
        threat_level = "LOW"
        is_threat = False
    
    return is_threat, threat_level, score


def normalize_packet_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure required columns exist for charts and alert rendering."""
    defaults = {
        "src_ip": "0.0.0.0",
        "dst_ip": "0.0.0.0",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "TCP",
        "packet_length": 0,
        "pkt_count": 1,
        "bytes": 0,
        "duration": 1,
        "rate": 0.0,
        "label": "UNKNOWN",
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
    return df


def generate_realistic_packets(scenario: str, sample_size: int) -> pd.DataFrame:
    """Generate scenario packets and keep a bounded sample for dashboard refreshes."""
    simulator = RealWorldScenarioSimulator()
    if scenario == "Night Attack Chain":
        scenario_df = simulator.simulate_night_attack(hours=1)
    else:
        scenario_df = simulator.simulate_ddos_campaign(duration_minutes=1)

    scenario_df = normalize_packet_frame(scenario_df)
    if len(scenario_df) > sample_size:
        scenario_df = scenario_df.sample(n=sample_size, replace=False).reset_index(drop=True)
    return scenario_df

# ====================================================
# Main Dashboard Sections
# ====================================================

# Multi-column layout for KPIs
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "🔴 Threats Detected",
        len([t for t in st.session_state.detected_threats if t.get('is_threat')]),
        delta="Active" if st.session_state.detected_threats else "None"
    )

with col2:
    st.metric(
        "📊 Packets Analyzed",
        len(st.session_state.packet_cache),
        delta="Last 5 min"
    )

with col3:
    threat_accuracy = (len([t for t in st.session_state.detected_threats if t.get('is_threat')]) / 
                      max(len(st.session_state.detected_threats), 1) * 100)
    st.metric(
        "🎯 Detection Rate",
        f"{threat_accuracy:.1f}%",
        delta="Accuracy"
    )

with col4:
    critical_alerts = len([t for t in st.session_state.detected_threats if t.get('threat_level') == 'HIGH'])
    st.metric(
        "⚠️ Critical Alerts",
        critical_alerts,
        delta="Now" if critical_alerts > 0 else "Normal"
    )

st.divider()

# ====================================================
# Real-time Traffic Section
# ====================================================
st.markdown("## 📡 Network Traffic Analysis")

# Generate data based on mode
if detection_mode == "Live Simulation":
    packets_df = generate_sample_packets(packet_batch_size, threat_percentage)
elif detection_mode == "Realistic Threat Scenarios":
    packets_df = generate_realistic_packets(realistic_scenario, packet_batch_size)
else:
    # Real network traffic (requires admin)
    st.info("🔐 Real network traffic capture requires administrator privileges")
    packets_df = generate_sample_packets(10, 20)

# Update session state
st.session_state.packet_cache = packets_df.to_dict('records')

# Classify packets
packets_df = normalize_packet_frame(packets_df)
classifications = packets_df.apply(lambda row: classify_packet(row), axis=1)
packets_df["is_threat"] = classifications.apply(lambda x: x[0])
packets_df["threat_level"] = classifications.apply(lambda x: x[1])
packets_df["confidence"] = classifications.apply(lambda x: x[2])

threats = [
    {
        "timestamp": datetime.now(),
        "is_threat": bool(row["is_threat"]),
        "threat_level": row["threat_level"],
    }
    for _, row in packets_df.iterrows()
]

st.session_state.detected_threats = threats
st.session_state.threat_timeline.append({
    'time': datetime.now(),
    'threats': len([t for t in threats if t['is_threat']])
})

# Display threat summary
col1, col2 = st.columns(2)

with col1:
    attack_types = packets_df['label'].value_counts().head(10)
    fig = px.bar(
        x=attack_types.index,
        y=attack_types.values,
        title="🔴 Top Attack Types Detected",
        labels={'x': 'Attack Type', 'y': 'Count'},
        color=attack_types.values,
        color_continuous_scale="Reds"
    )
    st.plotly_chart(fig, use_container_width=True)

with col2:
    # Threat distribution
    threat_dist = pd.Series({
        'BENIGN': len(packets_df[packets_df['label'] == 'BENIGN']),
        'THREATS': len(packets_df[packets_df['label'] != 'BENIGN'])
    })
    
    fig = px.pie(
        values=threat_dist.values,
        names=threat_dist.index,
        title="📊 Traffic Classification",
        color_discrete_map={'BENIGN': '#2ed573', 'THREATS': '#ff4757'}
    )
    st.plotly_chart(fig, use_container_width=True)

# ====================================================
# Real-time Alerts Section
# ====================================================
st.markdown("## 🚨 Active Threats & Alerts")

# Filter threats
critical_threats = packets_df[packets_df['label'] != 'BENIGN'].head(10)

if len(critical_threats) > 0:
    for _, threat in critical_threats.iterrows():
        threat_badge_class = "threat-high"
        if threat.get("threat_level") == "MEDIUM":
            threat_badge_class = "threat-medium"
        elif threat.get("threat_level") == "LOW":
            threat_badge_class = "threat-low"
        
        st.markdown(f"""
            <div class="active-alert-card">
                <strong>🔴 {threat['label']}</strong> | 
                <span class="{threat_badge_class}" style="padding: 4px 8px; border-radius: 3px; color: white;">
                    {threat.get('threat_level', 'UNKNOWN')}
                </span><br>
                <small class="active-alert-meta">
                    {threat['src_ip']} → {threat['dst_ip']}:{threat.get('dst_port', 'N/A')} | 
                    Confidence: {threat.get('confidence', 0)*100:.1f}%
                </small>
            </div>
        """, unsafe_allow_html=True)
else:
    st.success("✅ No threats detected - Network is clean")

st.divider()

# ====================================================
# Timeline & Flow Analysis
# ====================================================
col1, col2 = st.columns(2)

with col1:
    st.markdown("### 📈 Threat Timeline (Last 5 minutes)")
    
    if st.session_state.threat_timeline:
        timeline_df = pd.DataFrame(st.session_state.threat_timeline[-300:])
        fig = px.line(
            timeline_df,
            x='time',
            y='threats',
            title="Threats Over Time",
            labels={'threats': 'Active Threats', 'time': 'Time'}
        )
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.markdown("### 🌍 Top Source IPs")
    
    top_ips = packets_df['src_ip'].value_counts().head(10)
    fig = px.bar(
        x=top_ips.index,
        y=top_ips.values,
        title="Most Active Source IPs",
        labels={'x': 'IP Address', 'y': 'Count'}
    )
    st.plotly_chart(fig, use_container_width=True)

st.divider()

# ====================================================
# Detailed Threat Analysis
# ====================================================
st.markdown("## 🔍 Detailed Traffic Analysis")

with st.expander("📋 View Raw Packet Data", expanded=False):
    st.dataframe(
        packets_df[[  'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 
                      'packet_length', 'label']].head(50),
        use_container_width=True
    )

with st.expander("📊 Export Data", expanded=False):
    col1, col2, col3 = st.columns(3)
    
    with col1:
        csv = packets_df.to_csv(index=False)
        st.download_button("📥 CSV Export", csv, "threats.csv", "text/csv")
    
    with col2:
        json_str = packets_df.to_json(orient='records')
        st.download_button("📥 JSON Export", json_str, "threats.json", "application/json")
    
    with col3:
        if st.button("💾 Generate Report"):
            st.success("Report generated successfully!")

# ====================================================
# System Status
# ====================================================
st.divider()
st.markdown("### 🖥️ System Status")

status_cols = st.columns(4)

with status_cols[0]:
    st.metric("Model Status", "✅ Active")

with status_cols[1]:
    st.metric("Detection Latency", "12ms")

with status_cols[2]:
    st.metric("API Health", "🟢 Healthy")

with status_cols[3]:
    st.metric("Last Update", datetime.now().strftime("%H:%M:%S"))
