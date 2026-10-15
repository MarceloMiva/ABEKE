# Starter event_type -> MITRE ATT&CK technique map.
# Expand this as ABEKE learns new event types. Reference: https://attack.mitre.org
EVENT_TYPE_TO_MITRE = {
    "login_failed": ["T1110"],                      # Brute Force
    "login_success_after_failures": ["T1110", "T1078"],  # Brute Force -> Valid Accounts
    "port_scan": ["T1046"],                          # Network Service Discovery
    "malware_detected": ["T1204"],                   # User Execution
    "privilege_escalation": ["T1068"],                # Exploitation for Privilege Escalation
    "data_exfil_suspected": ["T1041"],                # Exfiltration Over C2 Channel
    "known_bad_ioc_hit": ["T1071"],                   # Application Layer Protocol (C2)
}


def map_techniques(event_types: list[str]) -> list[str]:
    techniques: set[str] = set()
    for et in event_types:
        techniques.update(EVENT_TYPE_TO_MITRE.get(et, []))
    return sorted(techniques)
