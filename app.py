from OTXv2 import OTXv2
from dotenv import load_dotenv
import os

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)
# attributes_and_methods = dir(otx)
# for x in attributes_and_methods:
#     print(x)

# Test: Get subscribed pulses
pulses = otx.get_my_pulses()
print(f"Retrieved {len(pulses)} pulses.")