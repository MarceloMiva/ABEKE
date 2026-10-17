import os
import json
import urllib.request

DISCORD_WEBHOOK_URL = os.environ.get("ABEKE_DISCORD_WEBHOOK", "")
TELEGRAM_BOT_TOKEN = os.environ.get("ABEKE_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("ABEKE_TELEGRAM_CHAT_ID", "")
SEVERITY_ALERT_THRESHOLD = float(os.environ.get("ABEKE_ALERT_THRESHOLD", "50"))


def _post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"[webhook] failed: {e}")
        return False


def send_discord(message: str) -> bool:
    if not DISCORD_WEBHOOK_URL:
        return False
    return _post_json(DISCORD_WEBHOOK_URL, {"content": message})


def send_telegram(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    return _post_json(url, {"chat_id": TELEGRAM_CHAT_ID, "text": message})


def notify_if_critical(incident) -> bool:
    if incident.severity_score < SEVERITY_ALERT_THRESHOLD or incident.webhook_sent:
        return False
    message = (
        f"🚨 ABEKE ALERT — {incident.title}\n"
        f"Severity: {incident.severity_score}/100\n"
        f"Status: {incident.status}\n"
        f"MITRE: {', '.join(incident.mitre_techniques) or 'none'}"
    )
    return send_discord(message) or send_telegram(message)
