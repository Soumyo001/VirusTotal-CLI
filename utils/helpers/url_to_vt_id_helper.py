import base64

def url_to_vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")