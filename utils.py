from OTXv2 import OTXv2
from dotenv import load_dotenv
import os
import pandas as pd
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


def search_pulses_by_category(category, max_results=20, modified_since_days=30):
    """Search pulses by tag/category, filtered by recent modifications."""
    # modified_since = (datetime.now() - timedelta(days=modified_since_days)).strftime('%Y-%m-%d')
    query = f"tag:{category}"
    # query = "tag:({})".format(" OR ".join(categories_tags[category]))
    pulses = otx.search_pulses(query, max_results=max_results)
    # pulses = otx.search_pulses(query, max_results=max_results, sort="modified")
    if not pulses:
        return pd.DataFrame()
    df = pd.DataFrame(pulses)

    # print(f"\n\n\n\ndf.columns={df.columns}\n\n\n\n")
    results_expanded = pd.json_normalize(df['results'])
    # print(f"\n\n\n\nresults_expanded.columns={results_expanded.columns}\n\n\n\n")
    pulse_details = pd.json_normalize(results_expanded['id'].apply(get_pulse_details))
    df = pd.concat([df.drop('results', axis=1), pulse_details], axis=1)

    # pulse_details = pd.json_normalize(results_expanded['indicators'])

    df['created'] = pd.to_datetime(df['created'], format="mixed")
    df['modified'] = pd.to_datetime(df['modified'], format="mixed")
    df = df[df["TLP"] == "white"]
    df.drop(columns=['groups', 'in_group', 'is_subscribing',
       'author.username', 'author.avatar_url',
       'author.is_subscribed', 'author.is_following'], inplace=True)
    if 'subscriber_count' in df.columns:
            df.sort_values(by=['modified', 'subscriber_count'], ascending=False, inplace=True)
    else:
         df.sort_values(by='modified', ascending=False, inplace=True)
    # Index(['count', 'exact_match', 'id', 'name', 'description', 'author_name',
    #    'modified', 'created', 'tags', 'references', 'public', 'adversary',
    #    'targeted_countries', 'malware_families', 'attack_ids', 'industries',
    #    'TLP', 'revision', 'groups', 'in_group', 'is_subscribing',
    #    'author.username', 'author.id', 'author.avatar_url',
    #    'author.is_subscribed', 'author.is_following'],
    #   dtype='object')

    # print(f"\n\n\n\n{df.columns}\n\n\n\n")

    indicators = df.iloc[1]['indicators'][:3]
    json_indicators = [json.dumps(x) for x in indicators]
    print("\n\n\n\n{}\n\n\n\n".format("\n\n".join(json_indicators)))

    # indicator = otx.get_indicator_details_full()
    # print("\n\n\n\n{}\n\n\n\n".format(json.dumps(indicator, indent=4)))

    # pulse_id = df.iloc[0]["id"]

    # pulse = otx.get_pulse_details(pulse_id)
    # print("\n\n\n\npulse details:\n{}\n\n\n\n".format(json.dumps(pulse, indent=4)))
    # pulse = otx.get_pulse_indicators(pulse_id)
    # print("\n\n\n\npulse indicators:\n{}\n\n\n\n".format(json.dumps(pulse, indent=4)))

    # print("\n\n\n\ndf.head()\n{}\n\n\n\n".format(df.head()))
    # 09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa
    # 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
    # 2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd

    return df

# Optional: Function to get details for a specific pulse
def get_pulse_details(pulse_id):
    return otx.get_pulse_details(pulse_id)


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
    