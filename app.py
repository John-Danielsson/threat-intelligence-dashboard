from OTXv2 import OTXv2
from dotenv import load_dotenv
import os
import utils
import streamlit as st
import plotly.express as px
import pandas as pd
import json
from utils import get_pulses, search_ioc, get_recent_pulses
from datetime import timedelta
import time


# otx = OTXv2(utils.OTX_API_KEY)

def main():

    st.title("Threat Intelligence Dashboard - AlienVault OTX")

    # Sidebar for navigation
    st.sidebar.title("Options")
    page = st.sidebar.radio("Select Page", ["Pulses Overview", "IOC Search", "Recent Pulse Activity"])  # New page added

    if page == "Pulses Overview":
        st.header("Recent Subscribed Pulses")
        pulses_df = get_pulses(count=50)
        st.dataframe(pulses_df)
        # Visualization: Pulse creation over time
        if not pulses_df.empty:
            pulses_df['created'] = pd.to_datetime(pulses_df['created'])
            pulses_df['month_year'] = pulses_df['created'].dt.strftime('%Y-%m')
            monthly_df = pulses_df.groupby('month_year').size().reset_index(name='pulse_count')
            fig = px.bar(monthly_df, x='month_year', y='pulse_count', title="Number of Pulses Over Time (Monthly Bins)")
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

    elif page == "Recent Pulse Activity":
        st.header("Recent Pulse Activity (Modified in Last 7 Days)")
        
        # Refresh button for manual polling
        if st.button("Refresh Recent Pulses"):
            with st.spinner("Polling OTX for recent activity..."):
                recent_df = get_recent_pulses(since_days=7)  # Poll here
            st.session_state['recent_pulses'] = recent_df  # Cache in session for display

        # Display cached data
        if 'recent_pulses' in st.session_state and not st.session_state['recent_pulses'].empty:
            st.dataframe(st.session_state['recent_pulses'])
            
            # Visualization: Recent pulses by modification date
            fig = px.bar(st.session_state['recent_pulses'], x='created', y='indicator', 
                        title="Recent Pulses IOC Counts by Modification Date",
                        hover_data=['title', 'type'])
            st.plotly_chart(fig)
        else:
            st.info("Click 'Refresh Recent Pulses' to poll OTX. No recent data loaded yet.")

        # # Optional: Auto-poll timer (uncomment to enable) -- WORK IN PROGRESS
        # refresh_period = 60
        # if st.button(f"Enable Auto-Refresh (every {refresh_period} seconds)"):
        #     while True:
        #         # Poll and update
        #         recent_df = get_recent_pulses(since_days=7)
        #         st.session_state['recent_pulses'] = recent_df
        #         st.experimental_rerun()  # Refresh UI
        #         time.sleep(refresh_period)

if __name__ == "__main__":

    # https://otx.alienvault.com/pulse/5dfcd90216eaf1abc9f675b3
    # https://otx.alienvault.com/user/AlienVault/pulses

    username = "AlienVault"
    main()
    

# =============== otx attributes ===============
# __class__
# __delattr__
# __dict__
# __dir__
# __doc__
# __eq__
# __firstlineno__
# __format__
# __ge__
# __getattribute__
# __getstate__
# __gt__
# __hash__
# __init__
# __init_subclass__
# __le__
# __lt__
# __module__
# __ne__
# __new__
# __reduce__
# __reduce_ex__
# __repr__
# __setattr__
# __sizeof__
# __static_attributes__
# __str__
# __subclasshook__
# __weakref__
# _get_paginated_resource
# add_or_update_pulse_indicators
# add_pulse_indicators
# cert
# clone_pulse
# create_indicator_detail_url
# create_pulse
# create_url
# delete_pulse
# edit_pulse
# fix_date
# follow_user
# get
# get_all_indicators
# get_indicator_details_by_section
# get_indicator_details_full
# get_my_pulses
# get_pulse_details
# get_pulse_indicators
# get_user
# get_user_pulses
# getall
# getall_iter
# getevents_since
# getsince
# getsince_iter
# group_add_pulse
# group_remove_pulse
# handle_response_errors
# headers
# key
# now
# patch
# post
# proxies
# remove_pulse_indicators
# replace_pulse_indicators
# request_session
# search_pulses
# search_users
# server
# session
# submit_file
# submit_url
# submit_urls
# submitted_files
# submitted_urls
# subscribe_to_pulse
# subscribe_to_user
# unfollow_user
# unsubscribe_from_pulse
# unsubscribe_from_user
# validate_indicator
# verify
# walkapi
# walkapi_iter