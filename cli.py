#!/usr/bin/env python3
"""
ABEKE — Automated Breach & Event Knowledge Engine
Interactive CLI front-end. Talks to the FastAPI backend (app/main.py)
running locally — start that first with:
    uvicorn app.main:app --reload --host 0.0.0.0
"""

import os
import sys
import json
import time
import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---- Blue theme (ANSI) ----
BLUE = "\033[38;5;33m"        # main banner / headline blue
LIGHT_BLUE = "\033[38;5;75m"  # acronym letters — lighter shade
MUTED_BLUE = "\033[38;5;67m"  # acronym words — muted shade
CYAN = "\033[38;5;45m"
DIM_BLUE = "\033[38;5;24m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"

ABEKE_ART = r"""
 █████╗ ██████╗ ███████╗██╗  ██╗███████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝
███████║██████╔╝█████╗  █████╔╝ █████╗
██╔══██║██╔══██╗██╔══╝  ██╔═██╗ ██╔══╝
██║  ██║██████╔╝███████╗██║  ██╗███████╗
╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
"""

ACRONYM = [
    ("A", "Automated"),
    ("B", "Breach &"),
    ("E", "Event"),
    ("K", "Knowledge"),
    ("E", "Engine"),
]

API_BASE = os.environ.get("ABEKE_API", "http://127.0.0.1:8000")

CATEGORIES = [
    ("Alert Ingestion",   "/ingest",        1, "ACTIVE"),
    ("Correlation Engine", "services/correlation.py", 1, "ACTIVE"),
    ("Severity Scoring",  "services/scoring.py",       1, "ACTIVE"),
    ("MITRE Mapping",     "services/mitre_mapping.py", 1, "ACTIVE"),
    ("IOC Extraction",    "services/ioc_extraction.py", 1, "ACTIVE"),
    ("Incident Store",    "/incidents",     4, "ACTIVE"),
    ("Knowledge Base",    "/iocs",          1, "ACTIVE"),
    ("Reporting",         "/incidents/{id}/report", 1, "ACTIVE"),
    ("Threat Intel Feed", "/intel",         2, "ACTIVE"),
    ("Playbook Automation", "/incidents/{id}/playbook", 1, "ACTIVE"),
    ("Live Dashboard",    "cli: dashboard", 1, "ACTIVE"),
]


def banner():
    print(f"{BLUE}{'=' * 60}{RESET}")
    for line in ABEKE_ART.strip("\n").split("\n"):
        print(f"{BOLD}{BLUE}{line}{RESET}")

    letters = "   ".join(f"{BOLD}{LIGHT_BLUE}{l}{RESET}" for l, _ in ACRONYM)
    words = "  ".join(f"{MUTED_BLUE}{w}{RESET}" for _, w in ACRONYM)
    print(("   " + letters).center(60 + len(letters) - 5))
    print(words.center(60 + len(words) - len(ACRONYM) * 9))

    print()
    print(f"{GRAY}{'Built in Termux. Trusted by the SOC.':^60}{RESET}")
    print(f"{BLUE}{'-' * 60}{RESET}")
    print(f"{DIM_BLUE} v0.1.0 | Author: Marcelo{RESET}")
    print(
        f"{WHITE}Modules loaded:{RESET} {CYAN}{len(CATEGORIES)}{RESET}"
        f"  |  {WHITE}Session started:{RESET} {CYAN}{datetime.datetime.now():%Y-%m-%d %H:%M:%S}{RESET}"
    )
    print()
    print(f"{BOLD}{YELLOW}ABEKE MODULE CATEGORIES{RESET}")
    print(f"{GRAY}{'#':<3}{'Category':<22}{'Entry Point':<28}{'Status'}{RESET}")
    print(f"{BLUE}{'-' * 60}{RESET}")
    for i, (name, entry, _count, status) in enumerate(CATEGORIES, 1):
        status_color = GREEN if status == "ACTIVE" else YELLOW
        print(f"{YELLOW}{i:<3}{RESET}{WHITE}{name:<22}{RESET}{CYAN}{entry:<28}{RESET}{status_color}{status}{RESET}")
    print()
    print(f"{BOLD}{WHITE}OPTIONS:{RESET}")
    print(f"  {CYAN}use <n>{RESET}            - Show details for a category")
    print(f"  {CYAN}status{RESET}             - Check if the ABEKE API is reachable")
    print(f"  {CYAN}ingest{RESET}             - Send a sample test event to the pipeline")
    print(f"  {CYAN}incidents{RESET}          - List open incidents from the API")
    print(f"  {CYAN}iocs{RESET}               - List known IOCs")
    print(f"  {CYAN}report <id>{RESET}        - Pull a markdown incident report")
    print(f"  {CYAN}playbook <id>{RESET}      - Show suggested response actions for an incident")
    print(f"  {CYAN}dashboard{RESET}          - Live auto-refreshing incident board (Ctrl+C to exit)")
    print(f"  {CYAN}intel update{RESET}       - Pull the latest known-bad IP feed (no API key needed)")
    print(f"  {CYAN}intel status{RESET}       - Show threat intel cache status")
    print(f"  {CYAN}help{RESET}               - Show this menu again")
    print(f"  {CYAN}exit{RESET}               - Exit ABEKE")
    print()


def api_get(path):
    if not HAS_REQUESTS:
        print(f"{YELLOW}requests not installed — run: pip install requests{RESET}")
        return None
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=5)
        return r.json()
    except Exception as e:
        print(f"{YELLOW}Couldn't reach ABEKE API at {API_BASE} — is uvicorn running?{RESET}")
        print(f"{GRAY}{e}{RESET}")
        return None


def api_post(path, payload):
    if not HAS_REQUESTS:
        print(f"{YELLOW}requests not installed — run: pip install requests{RESET}")
        return None
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload, timeout=5)
        return r.json()
    except Exception as e:
        print(f"{YELLOW}Couldn't reach ABEKE API at {API_BASE} — is uvicorn running?{RESET}")
        print(f"{GRAY}{e}{RESET}")
        return None


def cmd_status():
    data = api_get("/")
    if data:
        print(f"{GREEN}ABEKE API online{RESET} — {data}")


def cmd_ingest():
    sample = {
        "source": "cli-test",
        "event_type": "login_failed",
        "src_ip": "10.0.0.5",
        "raw_payload": {"user": "admin", "attempt": 1},
    }
    print(f"{GRAY}Sending sample event: {json.dumps(sample)}{RESET}")
    data = api_post("/ingest/event", sample)
    if data:
        print(f"{GREEN}Incident:{RESET} {data.get('title')}  "
              f"{CYAN}severity={data.get('severity_score')}{RESET}  "
              f"status={data.get('status')}")


def cmd_incidents():
    data = api_get("/incidents/")
    if data:
        if not data:
            print(f"{GRAY}No incidents yet — try 'ingest' first.{RESET}")
        for inc in data:
            print(f"{YELLOW}{inc['id'][:8]}{RESET}  {WHITE}{inc['title']:<30}{RESET}"
                  f"{CYAN}sev={inc['severity_score']:<6}{RESET}{GREEN}{inc['status']}{RESET}")


def cmd_iocs():
    data = api_get("/iocs/")
    if data:
        if not data:
            print(f"{GRAY}No IOCs recorded yet.{RESET}")
        for ioc in data:
            print(f"{CYAN}{ioc['ioc_type']:<8}{RESET}{WHITE}{ioc['value']:<30}{RESET}{YELLOW}{ioc['known_bad']}{RESET}")


def cmd_report(incident_id):
    data = api_get(f"/incidents/{incident_id}/report")
    if data:
        print(f"{BLUE}{'-' * 60}{RESET}")
        print(data.get("markdown", ""))
        print(f"{BLUE}{'-' * 60}{RESET}")


def cmd_playbook(incident_id):
    data = api_get(f"/incidents/{incident_id}/playbook")
    if data:
        print(f"{BOLD}{YELLOW}Suggested Response Actions:{RESET}")
        for block in data.get("playbook", []):
            print(f"{CYAN}{block['event_type']}{RESET}")
            for action in block["actions"]:
                print(f"  - {WHITE}{action}{RESET}")


def cmd_intel(sub):
    if sub == "update":
        print(f"{GRAY}Pulling latest threat feed (public list, no API key needed)...{RESET}")
        data = api_post("/intel/update", {})
        if data:
            if data.get("ok"):
                print(f"{GREEN}Loaded {data['count']} known-bad IPs into cache.{RESET}")
            else:
                print(f"{YELLOW}Feed update failed: {data.get('error')}{RESET}")
    elif sub == "status":
        data = api_get("/intel/status")
        if data:
            print(f"{CYAN}Threat intel cache:{RESET} {data}")
    else:
        print(f"{YELLOW}Usage: intel update | intel status{RESET}")


def cmd_dashboard():
    print(f"{GRAY}Live dashboard — refreshing every 4s. Press Ctrl+C to exit.{RESET}")
    try:
        while True:
            data = api_get("/incidents/")
            print("\033[2J\033[H", end="")
            print(f"{BOLD}{BLUE}{'ABEKE LIVE DASHBOARD':^60}{RESET}")
            print(f"{GRAY}{datetime.datetime.now():%Y-%m-%d %H:%M:%S}{RESET}")
            print(f"{BLUE}{'-' * 60}{RESET}")
            if data:
                if not data:
                    print(f"{GRAY}No incidents yet. Try 'ingest' from another session.{RESET}")
                for inc in sorted(data, key=lambda x: -x["severity_score"]):
                    sev = inc["severity_score"]
                    color = RED if sev >= 50 else (YELLOW if sev >= 20 else GREEN)
                    print(f"{color}[{sev:>5.1f}]{RESET} {WHITE}{inc['title']:<35}{RESET}{CYAN}{inc['status']}{RESET}")
            print(f"{BLUE}{'-' * 60}{RESET}")
            print(f"{GRAY}Ctrl+C to exit{RESET}")
            time.sleep(4)
    except KeyboardInterrupt:
        print(f"\n{CYAN}Exiting dashboard.{RESET}")


def cmd_use(n):
    try:
        idx = int(n) - 1
        name, entry, _count, status = CATEGORIES[idx]
        print(f"{BOLD}{CYAN}{name}{RESET}  ({entry})  — {GREEN}{status}{RESET}")
    except (ValueError, IndexError):
        print(f"{YELLOW}No such category: {n}{RESET}")


def main():
    banner()
    while True:
        try:
            raw = input(f"{BOLD}{BLUE}ABEKE{RESET} {GRAY}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd == "exit":
            print(f"{CYAN}Session closed.{RESET}")
            break
        elif cmd == "help":
            banner()
        elif cmd == "status":
            cmd_status()
        elif cmd == "ingest":
            cmd_ingest()
        elif cmd == "incidents":
            cmd_incidents()
        elif cmd == "iocs":
            cmd_iocs()
        elif cmd == "report" and len(parts) > 1:
            cmd_report(parts[1])
        elif cmd == "playbook" and len(parts) > 1:
            cmd_playbook(parts[1])
        elif cmd == "dashboard":
            cmd_dashboard()
        elif cmd == "intel" and len(parts) > 1:
            cmd_intel(parts[1])
        elif cmd == "use" and len(parts) > 1:
            cmd_use(parts[1])
        else:
            print(f"{YELLOW}Unknown command. Type 'help'.{RESET}")


if __name__ == "__main__":
    main()
