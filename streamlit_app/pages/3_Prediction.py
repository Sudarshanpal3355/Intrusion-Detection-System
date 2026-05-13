# ============================
# FIX: Add project root to Python path
# ============================
import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

# ============================
# Imports
# ============================
import streamlit as st
import pandas as pd
import numpy as np
import json
import plotly.express as px
from streamlit_lottie import st_lottie
from src.utils import load

st.set_page_config(layout="wide")

# ============================
# Modern Styling
# ============================
st.markdown("""
<style>
.main-title {
    font-size: 30px;
    font-weight: bold;
    color: #00e5ff;
}
.card {
    background-color: #111827;
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 15px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='main-title'>📊 Network Traffic Prediction Dashboard</div>", unsafe_allow_html=True)
st.markdown("---")

# ============================
# Load Artifacts
# ============================
@st.cache_resource
def load_artifacts():
    model = load("models/final_ids_model.pkl")
    preprocessor = load("models/encoder_scaler.pkl")
    selector = load("models/feature_selector.pkl")
    return model, preprocessor, selector

model, preprocessor, selector = load_artifacts()

# ============================
# Risk Helpers
# ============================
def risk_level(prob):
    if prob < 0.3:
        return "Low"
    elif prob < 0.6:
        return "Medium"
    else:
        return "High"

# ============================
# Upload CSV
# ============================
uploaded_file = st.file_uploader(
    "Upload Network Traffic CSV",
    type=["csv"]
)

if uploaded_file:

    df = pd.read_csv(uploaded_file)

    st.markdown("### 📄 Uploaded Data Preview")
    st.dataframe(df.head(), width="stretch")

    if st.button("🚀 Run AI Traffic Analysis"):

        with st.spinner("Analyzing network traffic..."):

            # ============================
            # Preprocess
            # ============================
            X_processed = preprocessor.transform(df)
            X_var = selector["variance_selector"].transform(X_processed)
            X = X_var[:, selector["top_feature_indices"]]

            # ============================
            # Predict
            # ============================
            probs = model.predict_proba(X).max(axis=1)

            df["Threat_Probability"] = probs
            df["Risk_Level"] = df["Threat_Probability"].apply(risk_level)

        st.markdown("---")

        # ============================
        # KPI SUMMARY
        # ============================
        total = len(df)
        high = len(df[df["Risk_Level"]=="High"])
        medium = len(df[df["Risk_Level"]=="Medium"])
        low = len(df[df["Risk_Level"]=="Low"])

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Records", total)
        col2.metric("High Risk", high)
        col3.metric("Medium Risk", medium)
        col4.metric("Low Risk", low)

        st.markdown("---")

        # ============================
        # Threat Distribution Chart
        # ============================
        risk_counts = df["Risk_Level"].value_counts().reset_index()
        risk_counts.columns = ["Risk_Level", "Count"]

        fig = px.pie(
            risk_counts,
            names="Risk_Level",
            values="Count",
            title="Threat Risk Distribution"
        )
        st.plotly_chart(fig, width="stretch")

        # ============================
        # Probability Histogram
        # ============================
        fig2 = px.histogram(
            df,
            x="Threat_Probability",
            nbins=20,
            title="Threat Probability Distribution"
        )
        st.plotly_chart(fig2, width="stretch")

        # ============================
        # Suspicious Records Table
        # ============================
        st.markdown("### 🚨 High-Risk Traffic Records")

        high_risk_df = df[df["Risk_Level"]=="High"]

        if len(high_risk_df) > 0:
            st.dataframe(high_risk_df.head(20), width="stretch")
            st.error("High-risk malicious traffic detected!")
        else:
            st.success("No high-risk traffic detected.")

        # ============================
        # Download Results
        # ============================
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Full Analysis Report",
            csv,
            "traffic_analysis_report.csv",
            "text/csv"
        )

        st.success("🎉 AI Traffic Analysis Completed Successfully!")