import re
from . import threat_intel

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ng|dev|xyz|ru|cn)\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(text_blob: str) -> list[dict]:
    known_bad_ips = threat_intel.load_known_bad()
    found = []

    for ip in set(IP_RE.findall(text_blob)):
        found.append({
            "ioc_type": "ip",
            "value": ip,
            "known_bad": "yes" if ip in known_bad_ips else "unknown",
        })

    for domain in set(DOMAIN_RE.findall(text_blob)):
        found.append({"ioc_type": "domain", "value": domain, "known_bad": "unknown"})

    for h in set(SHA256_RE.findall(text_blob)) | set(MD5_RE.findall(text_blob)):
        found.append({"ioc_type": "hash", "value": h, "known_bad": "unknown"})

    return found
