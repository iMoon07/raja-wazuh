#!/usr/bin/env python
#!/bin/sh

# Credit By ./M00NL16HT
# Github https://github.com/iMoon07

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# Replace with your actual chat ID
CHAT_ID = "<YOUR CHAT ID>"

# Read configuration parameters
alert_file = open(sys.argv[1])
hook_url = sys.argv[3]

# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract data fields
rule_id = alert_json['rule']['id'] if 'id' in alert_json['rule'] else "N/A"
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
timestamp = alert_json['timestamp'] if 'timestamp' in alert_json else "N/A"
srcip = alert_json.get('data', {}).get('srcip', "N/A")
full_log = alert_json['full_log'] if 'full_log' in alert_json else "N/A"
dstuser = alert_json['data']['dstuser'] if 'data' in alert_json and 'dstuser' in alert_json['data'] else "N/A"
rule_groups = ", ".join(alert_json['rule']['groups']) if 'rule' in alert_json and 'groups' in alert_json['rule'] and alert_json['rule']['groups'] else "N/A"

# Map Wazuh alert level to severity
def get_severity(level):
    try:
        level = int(level)
    except Exception:
        return "Unknown"
    if level >= 15:
        return "Critical severity"
    elif 12 <= level <= 14:
        return "High severity"
    elif 7 <= level <= 11:
        return "Medium severity"
    elif 0 <= level <= 6:
        return "Low severity"
    else:
        return "Unknown"

severity = get_severity(alert_level)

# Compose the message in the desired format
message = (
    f"🚨 Beruang Cyber Alert 🚨\n"
    f"🆔 Rule ID: `{rule_id}`\n"
    f"⚠️ Alert Level: `{alert_level}`\n"
    f"🔴 Severity: {severity}\n"
    f"🖥 Agent: `{agent}`\n"
    f"📝 Description: {description}\n"
    f"🕒 Time: {timestamp}\n"
    f"🌐 Source IP: {srcip}\n"
    # --- Penambahan ke dalam pesan ---
    f"📜 Full Log: `{full_log}`\n"
    f"🎯 Destination User: `{dstuser}`\n"
    f"📦 Rule Groups: `{rule_groups}`\n"
    # --- Akhir penambahan ---
    f"\n    🐻 Beruang Cyber Radar 🌐"
)

# Prepare data to send
msg_data = {
    'chat_id': CHAT_ID,
    'text': message,
    'parse_mode': 'Markdown'  # Enables bold, italic, code formatting
}

headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

# Send the request
requests.post(hook_url, headers=headers, data=json.dumps(msg_data))

sys.exit(0)
