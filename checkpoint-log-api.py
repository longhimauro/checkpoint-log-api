#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import urllib3
from dotenv import load_dotenv


# -----------------------------
# Helpers
# -----------------------------

def ask(prompt: str, default: str = "") -> str:
    if default:
        v = input(f"{prompt} [{default}]: ").strip()
        return v if v else default
    else:
        return input(f"{prompt}: ").strip()


def flatten_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (str, int, float, bool)):
        return str(v)
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def normalize_time(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        return raw.get("iso-8601", flatten_value(raw))
    if isinstance(raw, (int, float)):
        ts = raw / 1000 if raw > 10**12 else raw
        return datetime.fromtimestamp(ts).isoformat()
    return str(raw)


def extract_field(log: Dict[str, Any], candidates: List[str]) -> str:
    for k in candidates:
        if k in log and log[k] is not None and str(log[k]).strip():
            return flatten_value(log[k])
    return ""


def pick_logs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("logs", [])


def pick_query_id(data: Dict[str, Any]) -> str:
    return data.get("query-id", "")


def build_row(log: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Time": normalize_time(log.get("time")),
        "Blade": extract_field(log, ["blade", "product"]),
        "Action": extract_field(log, ["action"]),
        "Type": extract_field(log, ["type"]),
        "Interface": extract_field(log, ["ifname", "interface"]),
        "Origin": extract_field(log, ["origin", "gateway"]),
        "Source": extract_field(log, ["src", "src_ip"]),
        "Destination": extract_field(log, ["dst", "dst_ip"]),
        "Service": extract_field(log, ["service"]),
        "Access Rule Number": extract_field(log, ["rule_number", "rule_id"]),
        "Access Rule Name": extract_field(log, ["rule_name"]),
        "Description": extract_field(log, ["description", "message"]),
        "SNI": extract_field(log, ["sni"]),
        "TLS Server Host Name": extract_field(log, ["tls_server_host_name"]),
    }


# -----------------------------
# API Client
# -----------------------------

class CheckPointAPI:
    def __init__(self, mgmt_url: str):
        self.base = mgmt_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        urllib3.disable_warnings()

    def post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        r = self.session.post(f"{self.base}{path}", json=payload, verify=False)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} - {r.text}")
        return r.json()

    def login(self, user: str, password: str):
        data = self.post("/web_api/login", {"user": user, "password": password})
        self.session.headers["X-chkp-sid"] = data["sid"]

    def logout(self):
        try:
            self.post("/web_api/logout", {})
        except Exception:
            pass

    def show_logs_new(self, new_query: Dict[str, Any]) -> Dict[str, Any]:
        return self.post("/web_api/show-logs", {"new-query": new_query})

    def show_logs_next(self, query_id: str) -> Dict[str, Any]:
        return self.post("/web_api/show-logs", {"query-id": query_id})


# -----------------------------
# Main
# -----------------------------

def main():
    load_dotenv()

    api = CheckPointAPI(os.getenv("MGMT_URL"))
    api.login(os.getenv("API_USER"), os.getenv("API_PASSWORD"))

    print("\n--- Log query parameters ---\n")

    base_filter = ask("Base filter", os.getenv("LOG_FILTER", "service:https"))
    src_filter = ask("Source (src:)", os.getenv("SRC_FILTER", ""))
    dst_filter = ask("Destination (dst:)", os.getenv("DST_FILTER", ""))

    print("\nTime frame options:")
    print("1) last-24-hours")
    print("2) today")
    print("3) yesterday")
    print("4) last-7-days")
    print("5) custom (start/end)")

    tf_choice = ask("Choose", "1")

    new_query = {
        "filter": " ".join(
            x for x in [
                base_filter,
                f"src:{src_filter}" if src_filter else "",
                f"dst:{dst_filter}" if dst_filter else ""
            ] if x
        ),
        "type": "logs",
        "max-logs-per-request": int(os.getenv("MAX_PER_REQUEST", "100"))
    }

    if tf_choice == "5":
        start = ask("Custom start (YYYY-MM-DDTHH:MM:SS)")
        end = ask("Custom end   (YYYY-MM-DDTHH:MM:SS)")
        new_query["time-frame"] = "custom"
        new_query["custom-start"] = start
        new_query["custom-end"] = end
    else:
        frames = {
            "1": "last-24-hours",
            "2": "today",
            "3": "yesterday",
            "4": "last-7-days"
        }
        new_query["time-frame"] = frames.get(tf_choice, "last-24-hours")

    first = api.show_logs_new(new_query)

    logs = pick_logs(first)
    qid = pick_query_id(first)

    while qid:
        nxt = api.show_logs_next(qid)
        page = pick_logs(nxt)
        if not page:
            break
        logs.extend(page)
        qid = pick_query_id(nxt)

    with open("export_logs.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=build_row({}).keys())
        w.writeheader()
        for l in logs:
            w.writerow(build_row(l))

    print(f"\n✅ Export completato: {len(logs)} log")
    api.logout()


if __name__ == "__main__":
    main()
