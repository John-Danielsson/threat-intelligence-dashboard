import streamlit as st
from utils import search_pulses_by_category, categories
import plotly.express as px
import pandas as pd
import json

st.title("LevelBlue OTX Threat Intelligence Dashboard")

# Categories from your request
# categories = ["Ransomware", "Malware", "APT", "ICS"]

# Sidebar for category selection
st.sidebar.title("Categories")
selected_category = st.sidebar.radio("Select Feed Category", categories)

st.header(f"{selected_category.capitalize()} Threat Feed")

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
        df = search_pulses_by_category(selected_category.lower(), max_results=num_results)
    st.session_state[f'{selected_category}_df'] = df
    st.success(f"Fetched {len(df)} results", icon="✅")

# Display data if available
if f'{selected_category}_df' in st.session_state and not st.session_state[f'{selected_category}_df'].empty:
    df = st.session_state[f'{selected_category}_df']
    # print(f"\n\n\n\ndf.columns={df.columns}\n\n\n\n")
    # x = json.dumps(df['results'].iloc[0], indent=4)
    # print(f"\n\n\n\n{x}\n\n\n\n")
    st.dataframe(df)

    # Visualization: IOC counts over time (monthly bins)
    if not df.empty:
        # df['month'] = df['modified'].dt.strftime('%Y-%m')
        # monthly_df = df.groupby('month').sum().reset_index()
        # fig = px.bar(monthly_df, x='month', y='indicator_count', 
        #              title=f"{selected_category.capitalize()} IOC Trends Over Time")
        # st.plotly_chart(fig)
        pass
else:
    st.info(f"Click 'Refresh {selected_category} Pulses' to load data. No data loaded yet.")


if __name__ == "__main__":
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
