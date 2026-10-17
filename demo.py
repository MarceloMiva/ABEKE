#!/usr/bin/env python3
import os
import sys
import time
import random

try:
    import requests
except ImportError:
    print("Install requests first: pip install requests")
    sys.exit(1)

API_BASE = os.environ.get("ABEKE_API", "http://127.0.0.1:8000")
ATTACKERS = ["185.220.101.5", "45.155.205.233", "194.26.29.14", "91.219.236.18"]

SCENARIOS = [
    lambda ip: [
        {"source": "auth-log", "event_type": "login_failed", "src_ip": ip, "raw_payload": {"user": "admin", "attempt": 1}},
        {"source": "auth-log", "event_type": "login_failed", "src_ip": ip, "raw_payload": {"user": "admin", "attempt": 2}},
        {"source": "auth-log", "event_type": "login_failed", "src_ip": ip, "raw_payload": {"user": "admin", "attempt": 3}},
        {"source": "auth-log", "event_type": "login_success_after_failures", "src_ip": ip, "raw_payload": {"user": "admin", "attempt": 4}},
        {"source": "edr", "event_type": "privilege_escalation", "src_ip": ip, "raw_payload": {"user": "admin", "action": "sudo su"}},
    ],
    lambda ip: [
        {"source": "ids", "event_type": "port_scan", "src_ip": ip, "raw_payload": {"ports": "22,80,443,3306"}},
        {"source": "edr", "event_type": "malware_detected", "src_ip": ip, "raw_payload": {"file": "payload.exe", "hash": "d41d8cd98f00b204e9800998ecf8427e"}},
    ],
    lambda ip: [
        {"source": "netflow", "event_type": "data_exfil_suspected", "src_ip": ip, "dst_ip": "203.0.113.77", "raw_payload": {"bytes_out": 450000000}},
    ],
]


def run_demo():
    print(f"Flooding {API_BASE} with simulated attack traffic...\n")
    for scenario in SCENARIOS:
        ip = random.choice(ATTACKERS)
        for event in scenario(ip):
            try:
                r = requests.post(f"{API_BASE}/ingest/event", json=event, timeout=5)
                data = r.json()
                print(f"[+] {event['event_type']:<30} src={ip:<16} -> severity={data.get('severity_score')}")
            except Exception as e:
                print(f"[!] failed: {e}")
            time.sleep(0.6)
        print()
    print("Demo complete. Run 'dashboard' or 'incidents' in cli.py to see results.")


if __name__ == "__main__":
    run_demo()
