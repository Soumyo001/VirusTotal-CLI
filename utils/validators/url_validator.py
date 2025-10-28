import validators
import requests

def detect_protocol(domain: str):
    for scheme in ["https://", "http://"]:
        try:
            requests.head(scheme + domain, timeout=3)
            return scheme 
        except requests.exceptions.RequestException:
            continue
    return None


def validate_url(url: str) -> bool:
    if not url.startswith(("http://", "https://")):
        protocol = detect_protocol(url)
        if protocol is not None:
            url = protocol + url
    return validators.url(url) is True
