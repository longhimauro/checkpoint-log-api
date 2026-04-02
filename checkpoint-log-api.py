#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check Point Management API - API for Logs (show-logs)
- Login: /web_api/login
- Query logs: /web_api/show-logs con new-query.{filter,time-frame,max-logs-per-request,type,log-servers}
- Paginazione: /web_api/show-logs con query-id (senza max-logs-per-request, che può non essere supportato)
- Export CSV dei campi richiesti:
  Time, Blade, Action, Type, Interface, Origin, Source, Destination, Service,
  Access Rule Number, Access Rule Name, Description, SNI, TLS Server Host Name
"""

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

def env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


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
    """
    time nei log può arrivare come:
    - stringa ISO
    - dict con iso-8601
    - epoch (ms o s)
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        for k in ("iso-8601", "iso_8601", "iso8601", "iso"):
            if k in raw and raw[k]:
                return str(raw[k])
        return flatten_value(raw)
    if isinstance(raw, (int, float)):
        try:
            # se è in ms
            ts = raw / 1000 if raw > 10**12 else raw
            return datetime.fromtimestamp(ts).isoformat()
        except Exception:
            return str(raw)
    return str(raw)


def extract_field(log: Dict[str, Any], candidates: List[str]) -> str:
    """
    Estrae il primo campo non vuoto tra i possibili alias.
    """
    for k in candidates:
        if k in log and log[k] is not None and str(log[k]).strip() != "":
            return flatten_value(log[k])
    return ""


def pick_logs_from_response(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Tipicamente: {"logs":[...], "query-id":"..."}
    """
    if isinstance(data.get("logs"), list):
        return data["logs"]
    # fallback rari
    if isinstance(data.get("data"), list):
        return data["data"]
    if isinstance(data.get("objects"), list):
        return data["objects"]
    return []


def pick_query_id(data: Dict[str, Any]) -> str:
    for k in ("query-id", "query_id", "queryId"):
        if k in data and data[k]:
            return str(data[k])
    return ""


def build_row(log: Dict[str, Any]) -> Dict[str, str]:
    """
    Mappa i tuoi campi richiesti su possibili nomi presenti nel JSON log.
    Nota: alcuni campi possono non essere presenti per ogni record/blade.
    """
    return {
        "Time": normalize_time(log.get("time")),
        "Blade": extract_field(log, ["blade", "blades", "product", "module"]),
        "Action": extract_field(log, ["action", "act", "decision"]),
        "Type": extract_field(log, ["type", "log_type", "event_type"]),
        "Interface": extract_field(log, ["ifname", "interface", "in_interface", "out_interface", "inbound_if", "outbound_if"]),
        "Origin": extract_field(log, ["origin", "orig", "gateway", "gw", "originator", "gateway_name"]),
        "Source": extract_field(log, ["src", "src_ip", "source", "source_ip"]),
        "Destination": extract_field(log, ["dst", "dst_ip", "destination", "destination_ip"]),
        "Service": extract_field(log, ["service", "svc", "service_name", "proto", "protocol"]),
        "Access Rule Number": extract_field(log, ["rule_number", "rule-num", "rule_id", "rule-number"]),
        "Access Rule Name": extract_field(log, ["rule_name", "rule-name", "access_rule_name"]),
        "Description": extract_field(log, ["description", "desc", "message", "info"]),
        "SNI": extract_field(log, ["sni", "tls_sni", "server_name_indication"]),
        "TLS Server Host Name": extract_field(log, ["tls_server_host_name", "tls-server-host-name", "server_host_name", "tls_host_name"]),
    }


# -----------------------------
# API Client
# -----------------------------

class CheckPointAPI:
    def __init__(self, mgmt_url: str, verify_ssl: bool, timeout: int, debug: bool):
        self.mgmt_url = mgmt_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.debug = debug

        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        if not self.verify_ssl:
            urllib3.disable_warnings()

    def _post(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if payload is None:
            payload = {}

        url = f"{self.mgmt_url}{path}"

        if self.debug:
            print(f"\n[DEBUG] POST {url}")
            print("[DEBUG] Payload:", json.dumps(payload, indent=2, ensure_ascii=False))

        r = self.session.post(url, json=payload, verify=self.verify_ssl, timeout=self.timeout)

        if not r.ok:
            # stampa errore “vero” (utile)
            raise RuntimeError(f"HTTP {r.status_code} - {r.text}")

        data = r.json()

        if self.debug:
            print("[DEBUG] Response keys:", list(data.keys()))

        return data

    def login(self, user: str, password: str) -> None:
        data = self._post("/web_api/login", {"user": user, "password": password})
        sid = data.get("sid")
        if not sid:
            raise RuntimeError(f"Login OK ma SID mancante: {data}")
        self.session.headers.update({"X-chkp-sid": sid})

    def logout(self) -> None:
        try:
            self._post("/web_api/logout", {})  # body vuoto {}
        except Exception:
            pass

    def show_logs_new_query(
        self,
        log_filter: str,
        time_frame: str,
        max_per_request: int,
        log_type: str = "logs",
        log_servers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        # max-logs-per-request è valido QUI (new-query)
        new_query: Dict[str, Any] = {
            "filter": log_filter,
            "time-frame": time_frame,
            "max-logs-per-request": max_per_request,
            "type": log_type
        }
        if log_servers:
            new_query["log-servers"] = log_servers

        return self._post("/web_api/show-logs", {"new-query": new_query})

    def show_logs_next_page(self, query_id: str) -> Dict[str, Any]:
        # Nella tua versione: max-logs-per-request NON è accettato qui.
        # La size della pagina è determinata dalla query iniziale.
        return self._post("/web_api/show-logs", {"query-id": query_id})


# -----------------------------
# Main
# -----------------------------

def main() -> int:
    load_dotenv()

    mgmt_url = os.getenv("MGMT_URL", "").strip()
    api_user = os.getenv("API_USER", "").strip()
    api_password = os.getenv("API_PASSWORD", "").strip()

    if not mgmt_url or not api_user or not api_password:
        print("ERRORE: MGMT_URL, API_USER, API_PASSWORD devono essere definiti nel file .env", file=sys.stderr)
        return 2

    verify_ssl = env_bool("VERIFY_SSL", default=False)
    debug = env_bool("DEBUG", default=False)

    time_frame = os.getenv("TIME_FRAME", "last-24-hours").strip()
    log_filter = os.getenv("LOG_FILTER", "service:https").strip()
    log_type = os.getenv("LOG_TYPE", "logs").strip()  # "logs" o "audit"

    max_per_request = env_int("MAX_PER_REQUEST", 100)  # consigliato <= 100
    max_pages = env_int("MAX_PAGES", 10)

    out_csv = os.getenv("OUTPUT_CSV", "export_logs.csv").strip()

    log_servers_env = os.getenv("LOG_SERVERS", "").strip()
    log_servers = [s.strip() for s in log_servers_env.split(",") if s.strip()] if log_servers_env else None

    columns = [
        "Time", "Blade", "Action", "Type", "Interface", "Origin", "Source",
        "Destination", "Service", "Access Rule Number", "Access Rule Name",
        "Description", "SNI", "TLS Server Host Name"
    ]

    api = CheckPointAPI(mgmt_url=mgmt_url, verify_ssl=verify_ssl, timeout=60, debug=debug)

    try:
        api.login(api_user, api_password)

        first = api.show_logs_new_query(
            log_filter=log_filter,
            time_frame=time_frame,
            max_per_request=max_per_request,
            log_type=log_type,
            log_servers=log_servers
        )

        logs_all: List[Dict[str, Any]] = []
        logs_page = pick_logs_from_response(first)
        logs_all.extend(logs_page)

        query_id = pick_query_id(first)

        pages = 1
        while query_id and pages < max_pages:
            nxt = api.show_logs_next_page(query_id)
            logs_page = pick_logs_from_response(nxt)
            if not logs_page:
                break
            logs_all.extend(logs_page)
            # spesso query-id rimane lo stesso; se cambia lo aggiorniamo
            query_id = pick_query_id(nxt) or query_id
            pages += 1

        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=columns)
            w.writeheader()
            for lg in logs_all:
                w.writerow(build_row(lg))

        print(f"OK: esportati {len(logs_all)} log in '{out_csv}'")
        return 0

    except Exception as e:
        print("\nERRORE:", str(e), file=sys.stderr)
        if debug:
            import traceback
            traceback.print_exc()
        return 1

    finally:
        api.logout()


if __name__ == "__main__":
    raise SystemExit(main())
