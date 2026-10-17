import json
import os
import time
import urllib.request

FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
MIN_CONFIDENCE = 2

CACHE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "threat_feed_cache.json",
)


def _ensure_dir():
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)


def update_feed(min_confidence: int = MIN_CONFIDENCE) -> dict:
    _ensure_dir()
    bad_ips = set()
    try:
        with urllib.request.urlopen(FEED_URL, timeout=15) as resp:
            for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip, count = parts[0], parts[1]
                    try:
                        if int(count) >= min_confidence:
                            bad_ips.add(ip)
                    except ValueError:
                        continue
    except Exception as e:
        return {"ok": False, "error": str(e), "count": 0}

    cache = {"updated_at": time.time(), "ips": sorted(bad_ips)}
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)
    return {"ok": True, "count": len(bad_ips), "updated_at": cache["updated_at"]}


def load_known_bad() -> set:
    if not os.path.exists(CACHE_FILE):
        return set()
    try:
        with open(CACHE_FILE) as f:
            return set(json.load(f).get("ips", []))
    except Exception:
        return set()


def status() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {"cached": False, "count": 0}
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        return {"cached": True, "count": len(data.get("ips", [])), "updated_at": data.get("updated_at")}
    except Exception:
        return {"cached": False, "count": 0}
