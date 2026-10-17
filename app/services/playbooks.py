EVENT_TYPE_PLAYBOOKS = {
    "login_failed": [
        "Monitor for repeated attempts from this source",
        "If attempts exceed threshold, block the source IP at the firewall",
    ],
    "login_success_after_failures": [
        "Force a password reset for the affected account",
        "Enable MFA on the account if not already active",
        "Review the session for signs of lateral movement",
    ],
    "port_scan": [
        "Block the source IP at the perimeter firewall",
        "Identify which ports/services were probed",
        "Cross-check the scanned hosts against your asset inventory",
    ],
    "malware_detected": [
        "Isolate the affected host from the network immediately",
        "Run a full AV/EDR scan on the host",
        "Preserve the malicious artifact for forensic analysis",
        "Check other hosts for signs of lateral spread",
    ],
    "privilege_escalation": [
        "Review the account's current privileges immediately",
        "Rotate credentials for the affected account",
        "Audit recent administrative actions taken by the account",
    ],
    "data_exfil_suspected": [
        "Block outbound traffic to the suspected destination",
        "Preserve relevant network logs for investigation",
        "Escalate to the incident response lead immediately",
    ],
    "known_bad_ioc_hit": [
        "Block the IOC at the network perimeter",
        "Hunt for other systems that have contacted the same IOC",
        "Add the IOC to your long-term blocklist",
    ],
}

DEFAULT_PLAYBOOK = [
    "No predefined playbook for this event type yet — investigate manually and document findings."
]


def get_playbook(incident) -> list[dict]:
    seen_types = []
    for e in incident.events:
        if e.event_type not in seen_types:
            seen_types.append(e.event_type)

    return [
        {"event_type": et, "actions": EVENT_TYPE_PLAYBOOKS.get(et, DEFAULT_PLAYBOOK)}
        for et in seen_types
    ]
