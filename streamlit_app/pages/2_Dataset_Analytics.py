import streamlit as st
import pandas as pd
import plotly.express as px

df = pd.read_csv("data/UNSW_NB15_training-set.csv")

st.subheader("Attack Distribution")
fig = px.pie(df, names="label")
st.plotly_chart(fig, width="stretch")

st.subheader("Dataset Preview")
st.dataframe(df.head(100))
