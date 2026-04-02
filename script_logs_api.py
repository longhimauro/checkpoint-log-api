import os
import requests
import json
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings()

# =========================
# LOAD .env
# =========================
load_dotenv()

MGMT = os.getenv("MGMT_URL")
USER = os.getenv("API_USER")
PASS = os.getenv("API_PASSWORD")

if not all([MGMT, USER, PASS]):
    raise RuntimeError("Variabili d'ambiente mancanti. Controlla il file .env")

headers = {
    "Content-Type": "application/json"
}

# =========================
# LOGIN
# =========================
login_payload = {
    "user": USER,
    "password": PASS
}

r = requests.post(
    f"{MGMT}/web_api/login",
    json=login_payload,
    verify=False
)
r.raise_for_status()

sid = r.json()["sid"]
headers["X-chkp-sid"] = sid

# =========================
# QUERY LOG
# =========================
query_payload = {
    "new-query": {
        "filter": "service:https",
        "time-frame": "last-24-hours"
    },
    "fields": [
        "time",
        "blade",
        "action",
        "type",
        "ifname",
        "origin",
        "src",
        "dst",
        "dst_ip",
        "service",
        "rule_number",
        "rule_name",
        "description",
        "sni",
        "tls_server_host_name"
    ],
    "limit": 200
}

logs = requests.post(
    f"{MGMT}/web_api/show-logs",
    json=query_payload,
    headers=headers,
    verify=False
)
logs.raise_for_status()

print(json.dumps(logs.json(), indent=2))

# =========================
# LOGOUT
# =========================
requests.post(
    f"{MGMT}/web_api/logout",
    headers=headers,
    verify=False
)
