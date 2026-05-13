import requests
from typing import List

def get_public_ip() -> List[str]:
    sources = [
        ("http://ip-api.com/json", "query"),
        ("https://ifconfig.me/all.json", "ip_addr"),
        ("https://ipinfo.io/json", "ip"),
        ("https://api.ipify.org?format=json", "ip"),
    ]

    for url, key in sources:
        try:
            res = requests.get(url, timeout=3)
            data = res.json()
            ip = data.get(key)
            if ip: return [ip]
        except requests.RequestException:
            continue
    return []
