from OTXv2 import OTXv2
from dotenv import load_dotenv
import os
import utils
import streamlit as st
from utils import get_pulses, search_ioc
import plotly.express as px
import pandas as pd


otx = OTXv2(utils.OTX_API_KEY)

st.title("Threat Intelligence Dashboard - AlienVault OTX")

# Sidebar for navigation
st.sidebar.title("Options")
page = st.sidebar.radio("Select Page", ["Pulses Overview", "IOC Search"])

if page == "Pulses Overview":
    st.header("Recent Subscribed Pulses")
    pulses_df = get_pulses(count=20)
    st.dataframe(pulses_df)

    # Visualization: Pulse creation over time
    if not pulses_df.empty:
        fig = px.bar(pulses_df, x='created', y='indicator_count', title="Pulse IOC Counts Over Time")
        st.plotly_chart(fig)

elif page == "IOC Search":
    st.header("Search for IOCs")
    ioc_type = st.selectbox("IOC Type", ["IPv4", "domain", "hostname", "FileHash-MD5", "FileHash-SHA256"])
    ioc_value = st.text_input("Enter IOC Value (e.g., 8.8.8.8 or example.com)")
    
    if st.button("Search"):
        with st.spinner("Querying OTX..."):
            results = search_ioc(ioc_type, ioc_value)
        if results['pulses']:
            st.subheader("Associated Pulses")
            pulses_df = pd.DataFrame(results['pulses'])
            st.dataframe(pulses_df[['name', 'description']])
        else:
            st.info("No pulses found.")
        
        if results['malware']:
            st.subheader("Malware Associations")
            st.write(results['malware'])
        
        st.subheader("Reputation")
        st.json(results['reputation'])

if __name__ == "__main__":
    # attributes_and_methods = dir(otx)
    # for x in attributes_and_methods:
    #     print(x)

    # # Test: Get subscribed pulses
    # pulses = otx.get_my_pulses()
    # print(f"Retrieved {len(pulses)} pulses.")
    pass