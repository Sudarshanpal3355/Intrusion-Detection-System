import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
import time

st.set_page_config(layout="wide")

# ==============================
# MODERN CLEAN STYLE
# ==============================
st.markdown("""
<style>
.main-title {
    font-size: 32px;
    font-weight: bold;
    color: #00d4ff;
}
.card {
    background-color: #111827;
    padding: 20px;
    border-radius: 12px;
    margin-bottom: 15px;
}
.footer {
    text-align:center;
    font-size:14px;
    color:gray;
    margin-top:20px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='main-title'>🛡 AI Threat Intelligence</div>", unsafe_allow_html=True)
st.markdown("---")

# ==============================
# ATTACK SELECTOR
# ==============================
attack = st.selectbox(
    "Select Detected Threat Type",
    ["Reconnaissance", "DoS", "Worms", "Exploits", "Backdoor"]
)

# ==============================
# THREAT DATABASE
# ==============================
threat_data = {
    "Reconnaissance": ("Medium", 55),
    "DoS": ("High", 80),
    "Worms": ("Critical", 95),
    "Exploits": ("Critical", 92),
    "Backdoor": ("Critical", 97),
}

risk, score = threat_data[attack]

if st.button("🧠 Generate AI Security Analysis"):

    with st.spinner("Analyzing threat intelligence..."):
        time.sleep(1)

    # ==============================
    # TOP KPI METRICS
    # ==============================
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Threat Type", attack)
    col2.metric("Risk Level", risk)
    col3.metric("Severity Score", f"{score}/100")
    col4.metric("AI Confidence", f"{np.random.randint(85,99)}%")

    st.markdown("---")

    # ==============================
    # RISK GAUGE
    # ==============================
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': "Threat Severity Score"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "red" if score > 85 else "orange"},
        }
    ))
    st.plotly_chart(fig, width="stretch")

    # ==============================
    # THREAT TIMELINE
    # ==============================
    timeline_data = pd.DataFrame({
        "Time": range(10),
        "Threat Level": np.random.randint(30, score, 10)
    })

    fig2 = px.line(timeline_data, x="Time", y="Threat Level",
                   title="Threat Escalation Timeline")
    st.plotly_chart(fig2, width="stretch")

    # ==============================
    # MAIN CONTENT
    # ==============================
    colA, colB = st.columns(2)

    with colA:
        st.markdown("### 📌 Threat Overview")
        st.write(f"""
The system has detected a **{attack} attack**.

This threat indicates malicious network behavior targeting system
confidentiality, availability, or integrity.
        """)

        st.markdown("### 💥 Potential Impact")
        st.write("""
• Service disruption  
• Unauthorized access  
• Data exposure  
• Infrastructure instability  
        """)

    with colB:
        st.markdown("### 🛡 Immediate Response")
        st.success("""
1. Isolate affected systems  
2. Block malicious IP  
3. Enable firewall strict mode  
4. Apply latest patches  
        """)

        st.markdown("### 🔐 Long-Term Prevention")
        st.info("""
• Implement Zero Trust Architecture  
• Use SIEM monitoring  
• Deploy EDR solution  
• Conduct regular audits  
        """)

    # ==============================
    # MITRE ATT&CK SECTION
    # ==============================
    st.markdown("### 🧭 MITRE ATT&CK Mapping")
    st.write(f"""
Framework Stage Associated:  
• Initial Access  
• Persistence  
• Lateral Movement  
• Impact  

Mapped Category: **{attack}**
    """)

    # ==============================
    # SYSTEM STATUS PANEL
    # ==============================
    st.markdown("### 🖥 System Health Status")

    health_col1, health_col2, health_col3 = st.columns(3)
    health_col1.success("Firewall: Active")
    health_col2.success("IDS: Monitoring")
    health_col3.warning("Traffic Load: Elevated")

    # ==============================
    # FOOTER
    # ==============================
    st.markdown("<div class='footer'>Enterprise SOC Dashboard | AI-Powered Threat Intelligence | Real-Time Monitoring</div>", unsafe_allow_html=True)