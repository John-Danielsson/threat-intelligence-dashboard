import streamlit as st
import utils
import plotly.express as px
import pandas as pd
import json


page = st.sidebar.selectbox("Navigate", ["Threat Feeds", "IOC Lookup"])

if page == "Threat Feeds":

    st.title("LevelBlue OTX Threat Intelligence Dashboard")

    # Categories from your request
    # categories = ["Ransomware", "Malware", "APT", "ICS"]

    # Sidebar for category selection
    st.sidebar.title("Categories")
    selected_category = st.sidebar.radio("Select Feed Category", utils.categories)

    st.header(f"{selected_category} Threat Feed")

    # 1. Create the numeric input box
    # min_value=1 prevents negative/zero requests, step=10 ensures whole numbers
    num_results = st.number_input(
        "Max number of results to fetch:", 
        min_value=1, 
        max_value=10000, 
        value=100, 
        step=10
    )

    # Refresh button for polling
    if st.button(f"Refresh {selected_category} Pulses"):
        with st.spinner(f"Fetching recent {selected_category} pulses..."):
            df = utils.search_pulses_by_category(selected_category.lower(), max_results=num_results)
        st.session_state[f'{selected_category}_df'] = df
        st.success(f"Fetched {len(df)} results", icon="✅")

    #     if f'{selected_category}_df' in st.session_state and not st.session_state[f'{selected_category}_df'].empty:
    #         df = st.session_state[f'{selected_category}_df']
    #         st.dataframe(df)
            
    #         if not df.empty:
    #             fig = utils.create_country_heatmap(df)
    #             if fig:
    #                 st.plotly_chart(fig, use_container_width=True)
    #             else:
    #                 st.warning("No country data available in these pulses.")

    # # Call the fragment in your main app
    # display_threat_data(selected_category)

    @st.fragment(run_every=300)
    def display_threat_data(selected_category):
        # Display data if available
        if f'{selected_category}_df' in st.session_state and not st.session_state[f'{selected_category}_df'].empty:
            df = st.session_state[f'{selected_category}_df']
            st.dataframe(df)
            if not df.empty:
                fig = utils.create_country_heatmap(df)
                if fig:
                    st.plotly_chart(fig, width='stretch')
                else:
                    st.warning("No country data available in these pulses.")

        else:
            st.info(f"Click 'Refresh {selected_category} Pulses' to load data. No data loaded yet.")
    display_threat_data(selected_category)
else:
    st.title("🔍 Real-Time IOC Enrichment")
    st.markdown("Query for indicator details.")

    # 2. Search UI Components
    col1, col2 = st.columns([1, 3])
    with col1:
        # Define indicator types you want to support
        type_options = [type.name for type in utils.IndicatorTypes.all_types]
        indicator_type = st.selectbox("Indicator Type", options=type_options)

    with col2:
        indicator = st.text_input("Enter Indicator", placeholder="e.g. 1.1.1.1 or example.com")

    if st.button("Enrich IOC"):
        if indicator:
            with st.spinner(f"Querying for {indicator}..."):
                # Call your search function with the selected type and value
                utils.search_ioc(indicator_type, indicator)
        else:
            st.warning("Please enter a value to search.")


if __name__ == "__main__":
    # TODO
    # 1. Real-Time IOC Search and Enrichment
    # Add a search bar where users input an IOC (e.g., IP, domain, hash)
    # and get enriched details like reputation scores, associated pulses, or malware families from OTX.
    # This turns your dashboard into a quick lookup tool, similar to how analysts query threats during incidents. 
    # cycognito.com
    # Why good: Speeds up triage and correlates data across feeds (e.g., linking ransomware IOCs to APT tactics).
    # Implementation tip: Use OTXv2's get_indicator_details_full in a Streamlit text input/button. Display results
    # in a table with expandable JSON for depth. Poll for updates every 10-15 minutes via a refresh button to keep it "regular."
    
    # 2. Automated Threat Alerts
    # Integrate email/Slack notifications for new pulses matching your categories (ransomware, malware, APTs, ICS).
    # Set thresholds, like alerting on high-severity IOCs or surges in activity. 
    # fanruan.com
    # Why good: Shifts from passive viewing to proactive defense, mimicking SOAR features in
    # enterprise tools—essential for monitoring evolving threats like AI-driven ransomware. 
    # splunk.com
    # Implementation tip: Use schedule or Streamlit's st.experimental_rerun for periodic polling
    # (e.g., every hour). Send alerts via smtplib for email or slack-sdk—filter by tags like "ransomware" to avoid noise.

    # 3. Trend Visualization Over Time
    # Expand your existing charts to show threat trends, like IOC volume by
    # category over months or emerging tags (e.g., new APT techniques). 
    # cycognito.com +1
    # Why good: Helps spot patterns, such as rising ICS attacks, making your dashboard more analytical and valuable for reporting.
    # Implementation tip: Fetch historical pulses with OTX's modified_since parameter, group by date/tag in
    # Pandas, and plot with Plotly (e.g., line charts). Add filters for categories via Streamlit multiselect.
    
    # 4. IOC De-Duplication and Scoring
    # Automatically de-dupe repeated IOCs across feeds and assign risk scores (e.g., based on pulse subscriber count or severity tags). 
    # cycognito.com
    # Why good: Reduces clutter in high-volume feeds like malware pulses, prioritizing actionable intel—key
    # for APT/ICS where false positives waste time.
    # Implementation tip: Use Pandas drop_duplicates on fetched DataFrames, then score with a simple formula
    # (e.g., score = subscriber_count * indicator_count). Display in a sortable table.
    
    # 5. Integration with External Tools
    # Add buttons to export IOCs to formats like CSV/STIX or integrate with tools like Splunk (via API) for further analysis. 
    # splunk.com +1
    # Why good: Makes your dashboard interoperable, e.g., feeding ransomware IOCs into a
    # SIEM for correlation—boosting its utility for real-world SOC workflows.
    # Implementation tip: Use Streamlit's st.download_button for CSV exports. For Splunk, add a form
    # to push data via their REST API (requires Splunk creds).
    
    # 6. User Collaboration Features
    # Include a simple note-taking or tagging system for pulses, stored locally or in a SQLite DB, to simulate sharing within a team. 
    # cycognito.com
    # Why good: Encourages analysis of APT/ICS threats, turning your tool into a collaborative platform—valuable for portfolio demos.
    # Implementation tip: Use Streamlit session state or sqlite3 to save user notes per pulse ID. Display as expandable sections.

    # 7. Anomaly Detection
    # Implement basic ML to flag unusual patterns, like spikes in malware IOCs. 
    # splunk.com
    # Why good: Adds proactive value, e.g., alerting on rising APT activity—aligning with 2026 trends like AI-enhanced threats. 
    # darkreading.com
    # Implementation tip: Use scikit-learn's Isolation Forest on historical data (fetched via OTX). Visualize anomalies in charts.


    x = {
        "id": "60cb72752f16af56b91c84d7",
        "name": "PCode Pushing AveMaria",
        "description": "PCode Pushing AveMaria",
        "author_name": "the_good_guy",
        "modified": "2021-06-17T16:04:05.967000",
        "created": "2021-06-17T16:04:05.967000",
        "tags": [],
        "references": [],
        "public": 1,
        "adversary": "",
        "targeted_countries": [],
        "malware_families": [],
        "attack_ids": [],
        "industries": [],
        "TLP": "white",
        "revision": 1,
        "groups": [],
        "in_group": False,
        "author": {
            "username": "the_good_guy",
            "id": "38",
            "avatar_url": "/otxapi/users/avatar_image/media/avatars/the_good_guy/resized/80/images.jpeg",
            "is_subscribed": False,
            "is_following": False
        },
        "is_subscribing": None
    }
    # columns = list(x)
    # print(columns)
