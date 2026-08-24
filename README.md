# 🛡️ AI-Powered Intrusion Detection System

<div align="center">

### 🧠 Intelligent Network Security • Real-Time Threat Monitoring • Explainable AI

An AI-powered cybersecurity platform designed to detect suspicious network
traffic, classify threat levels, monitor network activity, and explain
machine-learning predictions through an interactive security dashboard.

<br>

[![🚀 Live Demo](https://img.shields.io/badge/🚀%20LIVE%20DEMO-Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://ai-intrusion-detection-system.streamlit.app/)
[![GitHub](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Sudarshanpal3355/Intrusion-Detection-System)

</div>

---

## ⚡ Technology Stack

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Scikit Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-013243?style=for-the-badge&logo=numpy&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![SHAP](https://img.shields.io/badge/SHAP-Explainable%20AI-6A1B9A?style=for-the-badge)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-4B8BBE?style=for-the-badge)

</div>

---

# 🚀 Project Overview

> **Transforming raw network traffic into actionable security intelligence.**

The **AI-Powered Intrusion Detection System (IDS)** is a machine-learning
based cybersecurity platform built to identify suspicious and potentially
malicious network activity.

The system processes network traffic, performs preprocessing and feature
selection, generates threat predictions, assigns risk levels, and presents
the results through a modern interactive security dashboard.

The project uses the **UNSW-NB15** dataset and integrates machine learning,
network analysis, visualization, real-time monitoring simulation, and
Explainable AI.

---

# 🔥 Core Features

<table>
<tr>
<td width="50%">

## 🧠 AI Threat Detection

Detect suspicious network traffic using a trained machine-learning model.

- Traffic classification
- Threat probability
- Automated risk assessment
- Feature preprocessing
- Feature selection

</td>

<td width="50%">

## 🚨 Risk Intelligence

Convert model predictions into understandable security levels.

🟢 **Low Risk**

🟡 **Medium Risk**

🔴 **High Risk**

</td>
</tr>

<tr>
<td width="50%">

## 📊 Security Analytics

Interactive visualizations for understanding network activity.

- Threat distribution
- Probability analysis
- Traffic patterns
- Threat escalation
- Security metrics

</td>

<td width="50%">

## 🛡️ Live Monitoring

SOC-style simulated monitoring environment.

- Network traffic simulation
- Threat detection
- Risk monitoring
- Suspicious activity identification
- Real-time dashboard updates

</td>
</tr>

<tr>
<td width="50%">

## 🔍 Explainable AI

Understand why the model produces a prediction using **SHAP-based
explainability**.

- Feature importance
- Prediction explanation
- Threat interpretation
- Model transparency

</td>

<td width="50%">

## 📥 Security Reports

Export analyzed network traffic for further investigation.

- Prediction results
- Threat probability
- Risk levels
- CSV report generation

</td>
</tr>
</table>

---

# 🌐 Live Application

<div align="center">

## 🚀 Try the System

[![Open Live Application](https://img.shields.io/badge/OPEN%20LIVE%20APPLICATION-🚀-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://ai-intrusion-detection-system.streamlit.app/)

### 🔗 https://ai-intrusion-detection-system.streamlit.app/

</div>

---

# 🧩 System Architecture

```text
                    ┌─────────────────────────┐
                    │   Network Traffic CSV   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Data Preprocessing    │
                    │ Encoding + Scaling      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │    Feature Selection    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   Trained ML Model      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Threat Probability     │
                    └────────────┬────────────┘
                                 │
                                 ▼
              ┌──────────────────────────────────────┐
              │          Risk Classification         │
              └──────────────┬───────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
          🟢 LOW          🟡 MEDIUM       🔴 HIGH
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                 ┌─────────────────────────┐
                 │   Security Dashboard    │
                 └────────────┬────────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
        ┌─────────────────┐       ┌─────────────────┐
        │ Live Monitoring │       │ SHAP Explainability│
        └─────────────────┘       └─────────────────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                    ┌─────────────────────┐
                    │  Security Report    │
                    └─────────────────────┘


# 📊 Dashboard Modules

| Module | Description |
|---|---|
| 🏠 **Home** | Security overview, traffic metrics and visualization |
| 📊 **Prediction** | Upload CSV and perform network threat prediction |
| 🛡️ **Live Monitoring** | Monitor simulated network activity |
| 🔍 **Explainability** | Understand model prediction factors |
| 📥 **Reports** | Download analyzed traffic results |

---

# 🧠 Machine Learning Pipeline

### 1️⃣ Data Input

Network traffic data from the **UNSW-NB15** dataset.

### 2️⃣ Preprocessing

Network features are transformed using the project's preprocessing pipeline.

### 3️⃣ Feature Selection

Relevant features are selected before sending the data to the trained model.

### 4️⃣ Prediction

The trained intrusion-detection model generates prediction probabilities.

### 5️⃣ Risk Scoring

The prediction probability is converted into a security risk level.

### 6️⃣ Visualization

Results are displayed through interactive charts and security metrics.

### 7️⃣ Explainability

SHAP-based analysis helps interpret model predictions.

---

# 🛠️ Technology Ecosystem

## 💻 Core

| Technology | Purpose |
|---|---|
| 🐍 **Python** | Core programming language |
| 🧠 **Scikit-learn** | Machine learning |
| 🤖 **TensorFlow** | Deep learning |
| 🐼 **Pandas** | Data processing |
| 🔢 **NumPy** | Numerical computation |

## 📊 Visualization

| Technology | Purpose |
|---|---|
| 📈 **Plotly** | Interactive visualizations |
| 📊 **Matplotlib** | Data visualization |
| 🎨 **Seaborn** | Statistical visualization |

## 🛡️ Cybersecurity

| Technology | Purpose |
|---|---|
| 🕵️ **Scapy** | Network packet analysis |
| 🔍 **SHAP** | Explainable AI |
| 🚨 **IDS Pipeline** | Network threat detection |

## 🌐 Application & Deployment

| Technology | Purpose |
|---|---|
| ⚡ **Streamlit** | Interactive web application |
| 🌐 **Flask** | Web/API support |
| ☁️ **Streamlit Cloud** | Cloud deployment |

---

# 🔄 End-to-End Detection Flow

```text
┌──────────────────────────────┐
│     🌐 Network Traffic       │
│        / CSV Input           │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      ⚙️ Preprocessing        │
│   Encoding + Scaling         │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      🎯 Feature Selection    │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       🧠 ML Prediction       │
│    Trained IDS Model         │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      📊 Threat Probability   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       🚨 Risk Scoring        │
└──────────────┬───────────────┘
               │
        ┌──────┼──────┐
        ▼      ▼      ▼
      🟢 LOW 🟡 MEDIUM 🔴 HIGH
        │      │      │
        └──────┼──────┘
               │
               ▼
┌──────────────────────────────┐
│       📊 Security Dashboard  │
└──────────────┬───────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
┌──────────────┐ ┌──────────────┐
│ 🛡️ Live      │ │ 🔍 SHAP      │
│ Monitoring   │ │ Explainability│
└──────────────┘ └──────────────┘
        │             │
        └──────┬──────┘
               ▼
┌──────────────────────────────┐
│       📥 Security Report     │
└──────────────────────────────┘