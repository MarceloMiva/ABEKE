import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ng|dev|xyz|ru|cn)\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Starter list — swap for a real threat intel feed (AbuseIPDB, OTX, VirusTotal) later
KNOWN_BAD_SEED = set()


def extract_iocs(text_blob: str) -> list[dict]:
    """Scan a raw event's text for IOC patterns. Returns list of {type, value, known_bad}."""
    found = []

    for ip in set(IP_RE.findall(text_blob)):
        found.append({
            "ioc_type": "ip",
            "value": ip,
            "known_bad": "yes" if ip in KNOWN_BAD_SEED else "unknown",
        })

    for domain in set(DOMAIN_RE.findall(text_blob)):
        found.append({"ioc_type": "domain", "value": domain, "known_bad": "unknown"})

    for h in set(SHA256_RE.findall(text_blob)) | set(MD5_RE.findall(text_blob)):
        found.append({"ioc_type": "hash", "value": h, "known_bad": "unknown"})

    return found
