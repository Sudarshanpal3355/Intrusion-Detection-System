import streamlit as st
import importlib.util
import os
import json

# ============================
# Page configuration
# ============================
st.set_page_config(
    page_title="AI IDS",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================
# Load global CSS
# ============================
css_path = "streamlit_app/style.css"
if os.path.exists(css_path):
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
else:
    st.warning("⚠️ style.css not found")

# ============================
# Global helper (OPTIONAL)
# Can be reused by pages if imported
# ============================
def load_lottie(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ============================
# Sidebar
# ============================
st.sidebar.markdown("## 🔐 AI IDS")
st.sidebar.markdown("### Security Operations Center")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "📊 Dataset Analytics",
        "🔮 Prediction",
        "📡 Live Monitoring",
        "🤖 AI Explanation"
    ]
)

# ============================
# Page routing (SAFE, NO exec)
# ============================
page_map = {
    "🏠 Dashboard": "1_Home.py",
    "📊 Dataset Analytics": "2_Dataset_Analytics.py",
    "🔮 Prediction": "3_Prediction.py",
    "📡 Live Monitoring": "4_Live_Monitoring.py",
    "🤖 AI Explanation": "5_AI_Explanation.py"
}

page_file = f"streamlit_app/pages/{page_map[page]}"

if os.path.exists(page_file):
    spec = importlib.util.spec_from_file_location("page_module", page_file)
    page_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(page_module)
else:
    st.error("❌ Page file not found.")
