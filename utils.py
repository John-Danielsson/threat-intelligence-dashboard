from datetime import datetime, timedelta
import pandas as pd
from OTXv2 import OTXv2
from dotenv import load_dotenv
import os


load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX = OTXv2(OTX_API_KEY)


def get_pulses(count=10):
    pulses = OTX.get_my_pulses()[:count]  # Limit for demo
    df = pd.DataFrame(pulses)
    return df

def search_ioc(ioc_type, ioc_value):
    # ioc_type: 'IPv4', 'domain', 'FileHash-MD5', etc.
    details = OTX.get_indicator_details_full(ioc_type, ioc_value)
    # Flatten relevant sections (e.g., pulse_info, malware)
    results = {
        'pulses': details.get('pulse_info', {}).get('pulses', []),
        'malware': details.get('malware', []),
        'reputation': details.get('reputation', {})
    }
    return results

def get_recent_pulses(since_days=7):
    """Fetch pulses modified in the last X days."""
    modified_since = (datetime.now() - timedelta(days=since_days)).strftime('%Y-%m-%dT%H:%M:%S')
    # OTX.get_all_indicators()
    pulses = OTX.get_all_indicators(modified_since=modified_since, limit=50)  # Adjust limit as needed
    if not pulses:
        return pd.DataFrame()  # Empty DF if no recent activity
    df = pd.DataFrame(pulses)
    df.sort_values(by="created", ascending=False, inplace=True)
    # print(df.columns)
    # ['id', 'indicator', 'type', 'created', 'content', 'title', 'description', 'expiration', 'is_active', 'role']
    return df