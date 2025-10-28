def validate_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")