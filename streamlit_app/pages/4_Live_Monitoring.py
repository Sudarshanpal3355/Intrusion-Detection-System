# ============================
# PATH FIX
# ============================
import sys, os
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ============================
# IMPORTS
# ============================
import time
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import shap
from streamlit_autorefresh import st_autorefresh
from src.utils import load
import streamlit.components.v1 as components
import matplotlib.pyplot as plt

# ============================
# PAGE TITLE
# ============================
st.markdown("## 🛡️ AI Cyber Defense Platform")

# ============================
# AUDIO ENGINE
# ============================
def play_sound(path):
    if os.path.exists(path):
        components.html(
            f"""
            <audio autoplay>
                <source src="{path}" type="audio/mp3">
            </audio>
            """,
            height=0,
        )

# ============================
# SIDEBAR
# ============================
st.sidebar.markdown("### 🔊 Alert System")
sound_enabled = st.sidebar.toggle("Enable Alert Sounds", value=False)

st.sidebar.markdown("### 🚀 Advanced Detection")
zero_day_mode = st.sidebar.toggle("Enable Zero-Day Detection")

# ============================
# USER CONTROLS
# ============================
st.markdown("### 🎛️ Attack Control Panel")

c1, c2, c3, c4 = st.columns(4)

with c1:
    attack_rate = st.slider("⚔️ Attack Intensity", 0.0, 1.0, 0.5)

with c2:
    traffic_volume = st.slider("🌐 Traffic Volume", 200, 2000, 800)

with c3:
    attack_type = st.selectbox(
        "🧬 Attack Type",
        ["Auto", "DoS", "Reconnaissance", "Exploits", "Backdoor", "Worms"]
    )

with c4:
    speed = st.selectbox("⏱ Simulation Speed", ["Slow", "Normal", "Burst"])

speed_map = {"Slow": 3000, "Normal": 1500, "Burst": 600}
st_autorefresh(interval=speed_map[speed], key="soc_refresh")

st.markdown("---")

# ============================
# LOAD MODEL PIPELINE
# ============================
@st.cache_resource
def load_artifacts():
    model = load("models/final_ids_model.pkl")
    preprocessor = load("models/encoder_scaler.pkl")
    selector = load("models/feature_selector.pkl")
    feature_names = load("models/feature_names.pkl")
    final_feature_names = load("models/final_feature_names.pkl")

    cat_cols = preprocessor.transformers_[1][2]
    cat_encoder = preprocessor.named_transformers_["cat"]

    cat_values = {
        col: list(cat_encoder.categories_[i])
        for i, col in enumerate(cat_cols)
    }

    return (
        model,
        preprocessor,
        selector,
        feature_names,
        cat_cols,
        cat_values,
        final_feature_names,
    )

(
    model,
    preprocessor,
    selector,
    feature_names,
    categorical_cols,
    categorical_values,
    final_feature_names,
) = load_artifacts()

# ============================
# SESSION STATE
# ============================
if "logs" not in st.session_state:
    st.session_state.logs = []

# ============================
# PACKET GENERATOR
# ============================
def generate_live_packet(rate, volume):
    pkt = {}

    for col in feature_names:
        if col in categorical_cols:
            pkt[col] = np.random.choice(categorical_values[col])
        else:
            pkt[col] = float(np.random.normal(0, 1))

    if "sbytes" in pkt:
        pkt["sbytes"] = float(np.random.randint(200, volume))
    if "spkts" in pkt:
        pkt["spkts"] = float(np.random.randint(2, 40))
    if "rate" in pkt:
        pkt["rate"] = float(np.random.uniform(0.5, 5))

    if np.random.rand() < rate:
        if "sbytes" in pkt:
            pkt["sbytes"] *= np.random.randint(10, 20)
        if "spkts" in pkt:
            pkt["spkts"] *= np.random.randint(15, 30)
        if "rate" in pkt:
            pkt["rate"] *= np.random.uniform(10, 25)

    df = pd.DataFrame([pkt])

    for col in categorical_cols:
        df[col] = df[col].astype(str)

    return df

packet = generate_live_packet(attack_rate, traffic_volume)

# ============================
# MODEL PREDICTION
# ============================
X_proc = preprocessor.transform(packet)
X_var = selector["variance_selector"].transform(X_proc)
X = X_var[:, selector["top_feature_indices"]]

prob = float(model.predict_proba(X).max())
is_attack = prob > 0.5

# ============================
# ALERT STATE
# ============================
if prob >= 0.65:
    state = "CRITICAL"
elif prob >= 0.35:
    state = "ALERT"
else:
    state = "CALM"

recent = st.session_state.logs[-3:]
if len(recent) == 3 and all(r["Attack"] == "YES" for r in recent):
    state = "CRITICAL"

if zero_day_mode:
    anomaly_score = abs(prob - 0.5)
    if anomaly_score > 0.45:
        state = "CRITICAL"
        st.warning("🚀 Zero-Day Pattern Detected")

# ============================
# SAVE LOG
# ============================
st.session_state.logs.append({
    "Time": time.strftime("%H:%M:%S"),
    "Attack": "YES" if is_attack else "NO",
    "Confidence": round(prob * 100, 2),
    "State": state
})

if len(st.session_state.logs) > 200:
    st.session_state.logs = st.session_state.logs[-200:]

# ============================
# ALERT DISPLAY
# ============================
if state == "CRITICAL":
    st.error("🚨 CRITICAL INTRUSION DETECTED")
    if sound_enabled:
        play_sound("streamlit_app/assets/alert_beep.mp3")
elif state == "ALERT":
    st.warning("⚠️ Suspicious Activity")
else:
    st.success("🟢 System Operating Normally")

# ============================
# METRICS
# ============================
col1, col2, col3 = st.columns(3)
col1.metric("Threat Confidence", f"{prob*100:.2f}%")
col2.metric("Recent Attacks (10)", sum(r["Attack"]=="YES" for r in st.session_state.logs[-10:]))
col3.metric("Mode", speed)
st.progress(min(prob,1.0))

# ============================
# TREND GRAPH
# ============================
chart_df = pd.DataFrame(st.session_state.logs)
if not chart_df.empty:
    fig = px.line(chart_df, y="Confidence", title="Threat Confidence Timeline")
    st.plotly_chart(fig, width="stretch")

# ============================
# 🧠 SHAP MODULE (FINAL SAFE VERSION)
# ============================

if state != "CALM":

    st.markdown("## 🧠 SHAP Explanation")

    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)

        # ----------------------------
        # Handle binary classifier
        # ----------------------------
        if isinstance(shap_values, list):
            shap_values = shap_values[1]  # select attack class

        shap_values = np.array(shap_values)

        # If 3D (n, f, 2) → take class dimension
        if shap_values.ndim == 3:
            shap_values = shap_values[:, :, 0]

        # Now select first sample
        shap_single = shap_values[0]

        # Force flatten
        shap_single = np.ravel(shap_single)

        # Align feature names safely
        min_len = min(len(final_feature_names), len(shap_single))
        feature_names_safe = final_feature_names[:min_len]
        shap_single = shap_single[:min_len]

        # ----------------------------
        # LOCAL BAR CHART
        # ----------------------------
        shap_df = pd.DataFrame({
            "Feature": feature_names_safe,
            "Impact": shap_single
        })

        shap_df = shap_df.sort_values(
            by="Impact",
            key=lambda x: abs(x),
            ascending=False
        ).head(10)

        fig_local = px.bar(
            shap_df,
            x="Impact",
            y="Feature",
            orientation="h",
            title="Top Feature Contributions"
        )

        st.plotly_chart(fig_local, width="stretch")

        # ----------------------------
        # WATERFALL
        # ----------------------------
        expected_value = explainer.expected_value

        if isinstance(expected_value, list):
            expected_value = expected_value[1]

        expected_value = float(np.ravel(expected_value)[0])

        shap_exp = shap.Explanation(
            values=shap_single,
            base_values=expected_value,
            data=X[0][:min_len],
            feature_names=feature_names_safe
        )

        import matplotlib.pyplot as plt
        fig, ax = plt.subplots()
        shap.plots.waterfall(shap_exp, show=False)
        st.pyplot(fig)

    except Exception as e:
        st.error(f"SHAP error: {str(e)}")

# ============================
# DRIFT MONITOR
# ============================
st.markdown("## 📉 Model Drift Monitoring")

if len(st.session_state.logs) > 20:
    recent_conf = [r["Confidence"] for r in st.session_state.logs[-20:]]
    historical_conf = [r["Confidence"] for r in st.session_state.logs[:20]]

    drift_score = abs(np.mean(recent_conf) - np.mean(historical_conf))

    st.metric("Drift Score", f"{drift_score:.2f}")

    if drift_score > 15:
        st.error("⚠️ Potential Model Drift")
    else:
        st.success("Model Stable")

# ============================
# 🇮🇳 COMPLETE INDIA MAP (All States + UTs)
# ============================

if state != "CALM":

    st.markdown("## GEO IP MAP")

    india_states = {
        # STATES
        "Andhra Pradesh - Amaravati": [16.5062, 80.6480],
        "Arunachal Pradesh - Itanagar": [27.0844, 93.6053],
        "Assam - Dispur": [26.1408, 91.7900],
        "Bihar - Patna": [25.5941, 85.1376],
        "Chhattisgarh - Raipur": [21.2514, 81.6296],
        "Goa - Panaji": [15.4909, 73.8278],
        "Gujarat - Gandhinagar": [23.2156, 72.6369],
        "Haryana - Chandigarh": [30.7333, 76.7794],
        "Himachal Pradesh - Shimla": [31.1048, 77.1734],
        "Jharkhand - Ranchi": [23.3441, 85.3096],
        "Karnataka - Bengaluru": [12.9716, 77.5946],
        "Kerala - Thiruvananthapuram": [8.5241, 76.9366],
        "Madhya Pradesh - Bhopal": [23.2599, 77.4126],
        "Maharashtra - Mumbai": [19.0760, 72.8777],
        "Manipur - Imphal": [24.8170, 93.9368],
        "Meghalaya - Shillong": [25.5788, 91.8933],
        "Mizoram - Aizawl": [23.7271, 92.7176],
        "Nagaland - Kohima": [25.6747, 94.1100],
        "Odisha - Bhubaneswar": [20.2961, 85.8245],
        "Punjab - Chandigarh": [30.7333, 76.7794],
        "Rajasthan - Jaipur": [26.9124, 75.7873],
        "Sikkim - Gangtok": [27.3389, 88.6065],
        "Tamil Nadu - Chennai": [13.0827, 80.2707],
        "Telangana - Hyderabad": [17.3850, 78.4867],
        "Tripura - Agartala": [23.8315, 91.2868],
        "Uttar Pradesh - Lucknow": [26.8467, 80.9462],
        "Uttarakhand - Dehradun": [30.3165, 78.0322],
        "West Bengal - Kolkata": [22.5726, 88.3639],

        # UNION TERRITORIES
        "Andaman & Nicobar - Port Blair": [11.6234, 92.7265],
        "Chandigarh - Chandigarh": [30.7333, 76.7794],
        "Dadra & Nagar Haveli and Daman & Diu - Daman": [20.3974, 72.8328],
        "Delhi - New Delhi": [28.6139, 77.2090],
        "Jammu & Kashmir - Srinagar": [34.0837, 74.7973],
        "Ladakh - Leh": [34.1526, 77.5770],
        "Lakshadweep - Kavaratti": [10.5667, 72.6417],
        "Puducherry - Puducherry": [11.9416, 79.8083],
    }

    # Simulate attack origin
    location = np.random.choice(list(india_states.keys()))
    lat, lon = india_states[location]

    map_df = pd.DataFrame({
        "lat": [lat],
        "lon": [lon]
    })

    st.map(map_df)

    st.info(f"⚠️ Simulated Attack Origin: {location}")

st.caption("🚀 Enterprise IDS | Stable | SHAP | Drift | GeoIP | Zero-Day")