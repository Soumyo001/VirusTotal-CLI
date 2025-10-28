import hashlib
import os

def compute_hashes(file_path: str):
    if not os.path.exists(file_path):
        print("[✗] Error: File not found")

    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
        
    return {
        "SHA256": sha256_hash.hexdigest(),
        "MD5": md5_hash.hexdigest(),
        "SHA1": sha1_hash.hexdigest()
    }