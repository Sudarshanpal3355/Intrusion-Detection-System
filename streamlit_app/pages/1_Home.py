import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import json
import os
from streamlit_lottie import st_lottie

# ============================
# Helper: Load Lottie JSON
# ============================
def load_lottie(path):
    if not os.path.exists(path):
        st.error(f"Lottie file not found: {path}")
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ============================
# Page Title & Intro
# ============================
st.title("🚀 AI-Powered Intrusion Detection System")

st.markdown("""
✔ **Machine Learning based detection**  
✔ **Generative AI for rare attack handling**  
✔ **Real-time SOC monitoring**  
✔ **Intelligent attack explanation**  
✔ **Industry-style dashboard**
""")

st.success("📊 Dataset Used: **UNSW-NB15**")

# ============================
# Cyber Animation (Lottie)
# ============================
lottie_cyber = load_lottie("streamlit_app/assets/cyber_animation.json")

if lottie_cyber:
    st_lottie(lottie_cyber, height=280, loop=True)

# ============================
# TOP METRICS (Glass Cards)
# ============================
st.markdown("## 🔐 AI Intrusion Detection Dashboard")

col1, col2, col3, col4 = st.columns(4)

metrics = [
    ("Total Traffic", "1.28M"),
    ("Attacks Detected", "24,381"),
    ("High Risk", "7,142"),
    ("System Status", "ACTIVE")
]

for col, (title, value) in zip([col1, col2, col3, col4], metrics):
    with col:
        st.markdown(f"""
        <div class="glass">
            <div class="subtext">{title}</div>
            <div class="metric">{value}</div>
        </div>
        """, unsafe_allow_html=True)

# ============================
# TRAFFIC SIMULATION CHART
# ============================
time = pd.date_range("2024-01-01", periods=50)
traffic = np.random.randint(200, 500, size=50)
attacks = np.random.randint(20, 200, size=50)

df = pd.DataFrame({
    "Time": time,
    "Normal Traffic": traffic,
    "Attacks": attacks
})

fig = px.line(
    df,
    x="Time",
    y=["Normal Traffic", "Attacks"],
    color_discrete_sequence=["#00fff0", "#ff4d4d"]
)

fig.update_layout(
    height=420,
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font_color="#e6f1ff",
    legend_title_text=""
)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<div class='glass'>", unsafe_allow_html=True)
st.plotly_chart(fig, width="stretch")
st.markdown("</div>", unsafe_allow_html=True)

# ============================
# RECENT EVENTS TABLE
# ============================
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<div class='glass'>", unsafe_allow_html=True)

st.markdown("### 🔎 Recent Traffic Events")

table_df = pd.DataFrame({
    "Packet ID": np.arange(1001, 1011),
    "Type": np.random.choice(["Normal", "Attack"], 10),
    "Risk Score": np.random.randint(10, 95, 10),
    "Status": np.random.choice(["Allowed", "Blocked"], 10)
})

st.dataframe(table_df, width="stretch")

st.markdown("</div>", unsafe_allow_html=True)
