#!/usr/bin/env python3
import os
import re
import sys
import time
import argparse

try:
    import requests
except ImportError:
    print("Install requests first: pip install requests")
    sys.exit(1)

PATTERNS = [
    (re.compile(r"Failed password", re.I), "login_failed"),
    (re.compile(r"Accepted password", re.I), "login_success_after_failures"),
    (re.compile(r"\b(nmap|masscan|port scan)\b", re.I), "port_scan"),
    (re.compile(r"\b(malware|trojan|virus detected)\b", re.I), "malware_detected"),
    (re.compile(r"sudo:.*COMMAND|privilege escalat", re.I), "privilege_escalation"),
]
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_line(line: str):
    for pattern, event_type in PATTERNS:
        if pattern.search(line):
            ip_match = IP_RE.search(line)
            return {
                "source": "log-tail",
                "event_type": event_type,
                "src_ip": ip_match.group(0) if ip_match else None,
                "raw_payload": {"line": line.strip()},
            }
    return None


def tail_file(path: str, api_base: str):
    print(f"Tailing {path} -> {api_base}  (Ctrl+C to stop)")
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            event = parse_line(line)
            if not event:
                continue
            try:
                r = requests.post(f"{api_base}/ingest/event", json=event, timeout=5)
                data = r.json()
                print(f"[+] {event['event_type']:<30} -> {data.get('title')} (sev={data.get('severity_score')})")
            except Exception as e:
                print(f"[!] failed to send event: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--api", default=os.environ.get("ABEKE_API", "http://127.0.0.1:8000"))
    args = parser.parse_args()
    try:
        tail_file(args.logfile, args.api)
    except KeyboardInterrupt:
        print("\nStopped.")
