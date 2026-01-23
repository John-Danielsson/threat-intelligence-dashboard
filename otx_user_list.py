import utils
import tqdm
import time
import json


OTX_USERS = [
    "METADEFENDER",
    "AlienVault",
    "LevelBlue",
    "CYBERHUNTERAUTOFEED",
    "SEVENTYSIX",
    "JAMESBRINE",
    "MALWAREPATROL"
]

OTX = utils.OTX

if __name__ == "__main__":
    # CYBERHUNTERAUTOFEED 6
    # SEVENTYSIX 200+
    username = "SEVENTYSIX"
    for p in OTX.get_user_pulses(username):
        print(p['name'])