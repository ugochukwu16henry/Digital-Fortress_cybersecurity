import requests
from app.core.config import settings

class BunkerWebAPI:
    def __init__(self):
        self.base_url = settings.bunkerweb_api_url.rstrip("/")
        self.api_key = settings.bunkerweb_api_key
        self.timeout = settings.bunkerweb_api_timeout

    def block_ip(self, ip: str, reason: str = "") -> bool:
        url = f"{self.base_url}/block"
        payload = {"ip": ip, "reason": reason}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False

    def challenge_ip(self, ip: str, reason: str = "") -> bool:
        url = f"{self.base_url}/challenge"
        payload = {"ip": ip, "reason": reason}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False

    # Optionally add more methods for hardware_id, etc.