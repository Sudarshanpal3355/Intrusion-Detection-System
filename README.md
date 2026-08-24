<!-- # Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10-blue?style=for-the-badge&logo=python)
![Machine Learning](https://img.shields.io/badge/Machine-Learning-orange?style=for-the-badge&logo=scikit-learn)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-yellow?style=for-the-badge&logo=scikit-learn)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-black?style=for-the-badge&logo=pandas)
![NumPy](https://img.shields.io/badge/NumPy-Numerical%20Computing-blue?style=for-the-badge&logo=numpy)
![GitHub Repo stars](https://img.shields.io/github/stars/Sudarshanpal3355/Intrusion-Detection-System?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/Sudarshanpal3355/Intrusion-Detection-System?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/Sudarshanpal3355/Intrusion-Detection-System?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
[![Streamlit App](https://img.shields.io/badge/Streamlit-Live%20Demo-red?style=for-the-badge&logo=streamlit)](YOUR_LINK)
![Accuracy](https://img.shields.io/badge/Accuracy-99%25-brightgreen?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?style=for-the-badge&logo=flask)
![TensorFlow](https://img.shields.io/badge/TensorFlow-Deep%20Learning-orange?style=for-the-badge&logo=tensorflow)

---

## 📌 Project Overview
A Machine Learning-based Intrusion Detection System designed to detect and classify malicious network activities and cyber attacks. The project analyzes network traffic data to identify suspicious behavior, improve cybersecurity, and prevent unauthorized access using intelligent prediction models and real-time monitoring techniques. -->





# 🛡️ AI-Powered Intrusion Detection System

[![Streamlit](https://img.shields.io/badge/Streamlit-Live%20Demo-FF4B4B?logo=streamlit&logoColor=white)](https://ai-intrusion-detection-system.streamlit.app/)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E?logo=scikit-learn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-Numerical%20Computing-013243?logo=numpy&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-Deep%20Learning-FF6F00?logo=tensorflow&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-Visualization-3F4F75?logo=plotly&logoColor=white)
![SHAP](https://img.shields.io/badge/SHAP-Explainable%20AI-6A1B9A)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Analysis-4B8BBE)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-000000?logo=flask&logoColor=white)
![Dataset](https://img.shields.io/badge/Dataset-UNSW--NB15-1976D2)
![License](https://img.shields.io/badge/License-MIT-green)

> **An intelligent network security platform for detecting, classifying, monitoring, and explaining suspicious network traffic using Machine Learning.**

---

## 🚀 Live Demo

### 👉 [Open AI Intrusion Detection System](https://ai-intrusion-detection-system.streamlit.app/)

The deployed application provides an interactive dashboard for network traffic prediction, threat-risk analysis, live monitoring, and explainable AI.

---

## 📌 Project Overview

The **AI-Powered Intrusion Detection System (IDS)** is a Machine Learning-based cybersecurity application designed to detect and classify malicious network activities.

The system analyzes network traffic, processes relevant features, predicts threat probability, assigns risk levels, and provides an interactive monitoring interface through Streamlit.

The project uses the **UNSW-NB15** dataset and combines machine learning, data preprocessing, visualization, network analysis, and explainable AI techniques to build an industry-style security monitoring dashboard.

---

## 🎯 Objectives

- Detect suspicious and malicious network traffic.
- Classify network activity based on predicted threat probability.
- Categorize traffic into Low, Medium, and High risk.
- Provide an interactive network traffic prediction interface.
- Simulate real-time security monitoring.
- Provide model explanations using SHAP.
- Generate downloadable traffic analysis reports.
- Present security information through a SOC-style dashboard.

---

## ✨ Key Features

### 📊 Network Traffic Prediction

Upload a network traffic CSV file and run the trained intrusion detection model to analyze the traffic.

### 🚨 Risk Classification

Each network record is assigned a threat probability and categorized as:

- 🟢 **Low Risk**
- 🟡 **Medium Risk**
- 🔴 **High Risk**

### 🛡️ Live Threat Monitoring

The Live Monitoring module provides a simulated real-time view of network activity and highlights suspicious traffic.

### 🔍 Explainable AI with SHAP

SHAP is integrated to help understand which features contribute to the model's predictions.

### 📈 Interactive Visualizations

The dashboard provides interactive charts for:

- Threat distribution
- Threat probability
- Traffic activity
- Threat escalation
- Security metrics

### 📥 Analysis Report

Prediction results can be exported as a CSV report for further analysis.

### 🎨 Interactive Dashboard

The application includes a modern cybersecurity-themed Streamlit interface with dashboard cards, charts, animations, and monitoring components.

---

## 🧠 System Workflow

```text
              Network Traffic / CSV
                       │
                       ▼
              Data Preprocessing
                       │
                       ▼
                Feature Encoding
                       │
                       ▼
                Feature Selection
                       │
                       ▼
              Trained ML Model
                       │
                       ▼
              Threat Probability
                       │
                       ▼
                Risk Classification
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
            Low     Medium     High
             │        │         │
             └────────┼─────────┘
                      ▼
             Security Dashboard
                      │
             ┌────────┴────────┐
             ▼                 ▼
       Live Monitoring    SHAP Explanation
             │                 │
             └────────┬────────┘
                      ▼
               Analysis Report