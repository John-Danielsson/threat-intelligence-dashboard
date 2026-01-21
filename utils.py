from OTXv2 import OTXv2
from dotenv import load_dotenv
import os
import pandas as pd

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

def get_pulses(count=10):
    pulses = otx.get_my_pulses()[:count]  # Limit for demo
    df = pd.DataFrame(pulses)
    return df

def search_ioc(ioc_type, ioc_value):
    # ioc_type: 'IPv4', 'domain', 'FileHash-MD5', etc.
    details = otx.get_indicator_details_full(ioc_type, ioc_value)
    # Flatten relevant sections (e.g., pulse_info, malware)
    results = {
        'pulses': details.get('pulse_info', {}).get('pulses', []),
        'malware': details.get('malware', []),
        'reputation': details.get('reputation', {})
    }
    return results