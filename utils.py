import streamlit as st
from OTXv2 import OTXv2, IndicatorTypes
from dotenv import load_dotenv
import os
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json


load_dotenv()
otx = OTXv2(os.getenv("OTX_API_KEY"))

# query = f"tag:({' OR '.join(categories)})"

categories = ["Ransomware", "Malware", "APT", "ICS"]
categories_tags = {
    "ransomware": ["ransomware"],
    "malware": ["malware"],
    "apt": ["apt"],
    "ics": ["ics", "scada", "ot"]
}
ioc_types = {t.name: t for t in IndicatorTypes.all_types}


# TODO:
# - add a more custom search (e.g. by category or name, or even a search bar)

def search_pulses_by_category(category, max_results=20, modified_since_days=30):
    """Search pulses by tag/category, filtered by recent modifications."""
    query = f"tag:{category}"
    # query = "tag:({})".format(" OR ".join(categories_tags[category]))
    pulses = otx.search_pulses(query, max_results=max_results)
    if not pulses:
        return pd.DataFrame()
    df = pd.DataFrame(pulses)
    results_expanded = pd.json_normalize(df['results'])
    pulse_details = pd.json_normalize(results_expanded['id'].apply(get_pulse_details))
    df = pd.concat([df.drop('results', axis=1), pulse_details], axis=1)
    df['created'] = pd.to_datetime(df['created'], format="mixed")
    df['modified'] = pd.to_datetime(df['modified'], format="mixed")
    df = df[df["TLP"] == "white"]
    # df['indicators_display'] = df['indicators'].apply(lambda x: ';'.join(x) if isinstance(x, list) else str(x))
    df.drop(columns=['groups', 'in_group', 'is_subscribing',
       'author.username', 'author.avatar_url',
       'author.is_subscribed', 'author.is_following', 'indicators'], inplace=True)
    if 'subscriber_count' in df.columns:
            df.sort_values(by=['modified', 'subscriber_count'], ascending=False, inplace=True)
    else:
         df.sort_values(by='modified', ascending=False, inplace=True)
    return df

# Optional: Function to get details for a specific pulse
def get_pulse_details(pulse_id):
    return otx.get_pulse_details(pulse_id)

def create_country_heatmap(df):
    if 'targeted_countries' not in df.columns:
        return None
    
    # 1. Flatten the list of countries into individual rows
    # OTX often stores these as a list; explode turns [US, UK] into two rows
    country_df = df.explode('targeted_countries')
    
    # 2. Count occurrences of each country
    counts = country_df['targeted_countries'].value_counts().reset_index()
    counts.columns = ['Country', 'Pulse Count']
    
    # 3. Create the choropleth map
    # 'Reds' scale makes higher counts darker/redder
    fig = px.choropleth(
        counts,
        locations="Country",
        locationmode="country names",
        color="Pulse Count",
        hover_name="Country",
        color_continuous_scale="Reds",
        title="Threat Pulse Distribution by Country"
    )
    
    fig.update_layout(margin={"r":0,"t":40,"l":0,"b":0})
    return fig

def ioc_df(ioc_details):
    data = pd.json_normalize(ioc_details)
    df = pd.DataFrame(data)
    for column in df.columns:
        df[column] = df[column].apply(
            lambda x: json.dumps(x) if isinstance(x, (dict, list)) else x
        )
    # def unpack_all_json()
    return df

def search_ioc(indicator_type, indicator):
    try:

        # Fetch data from LevelBlue OTX
        # ioc_types[indicator_type]
        ioc_details = otx.get_indicator_details_full(
            indicator_type=ioc_types[indicator_type],
            indicator=indicator
        )

        df = ioc_df(ioc_details)
        var_name = indicator_type.replace(" ", "_").lower()
        st.session_state[f'{var_name}_df'] = df
        st.success(f"Fetched IOC data.", icon="✅")
        
        # Streamlit's st.json renders the dictionary in an interactive, 
        # expandable format in your dashboard.
        st.subheader(f"Results for \"{indicator}\"")

        st.dataframe(
            df,
            height="stretch",
            column_config={
                "raw_details": st.column_config.JsonColumn(
                    "Full IOC Data",
                    help="Click to expand the JSON object",
                    width="large"
                )
            }
        )


        # st.dataframe(df, height="stretch")
        # # Enable row selection in the dataframe
        # event = st.dataframe(
        #     df, 
        #     on_select="rerun",  # Triggers a rerun when a row is clicked
        #     selection_mode="single-row",
        #     height=400
        # )
        # # Check if a row is selected
        # if event.selection.rows:
        #     selected_index = event.selection.rows[0]
        #     selected_row_data = df.iloc[selected_index]
            
        #     st.divider()
        #     st.subheader("Detailed JSON View")
        #     # Assume your JSON column is named 'raw_details'
        #     # You can use st.json for a pretty tree view or st.text for raw string
        #     st.json(selected_row_data['raw_details']) 


        
    except Exception as e:
        st.error(f"Error fetching data: {e}")


if __name__ == "__main__":

    tags = ["ransomware", "malware", "APT", "ICS"]

    # python -c "from utils import search_pulses_by_category; df = search_pulses_by_category('ransomware', 1000); print(df.head())"

    # https://otx.alienvault.com/pulse/5dfcd90216eaf1abc9f675b3
    # https://otx.alienvault.com/user/AlienVault/pulses

    # username = "AlienVault"
    # username = "LevelBlue"
    # username = "ALIENVAULT"
    username = "CYBERHUNTERAUTOFEED"
    # username = "METADEFENDER"

    types = IndicatorTypes.all_types
    