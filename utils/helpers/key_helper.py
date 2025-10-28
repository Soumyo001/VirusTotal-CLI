import os
import json
import sys
from data.api_constants import Paths as p

def save_api_key(key:str):
    os.makedirs(os.path.dirname(p.CONFIG_PATH), exist_ok=True)

    with open(p.CONFIG_PATH, "w", encoding='utf-8') as f:
        json.dump({p.API_KEY_ENTRY: key}, f)
    print("[✓] API key saved successfully.")

def load_api_key() -> str:
    if not os.path.exists(p.CONFIG_PATH):
        print("[!] API key not found. Please run 'vt setup --apikey <APIKEY>' first.")
        sys.exit(1)

    with open(p.CONFIG_PATH, "r", encoding='utf-8') as f:
        key = json.load(f).get(p.API_KEY_ENTRY)
        if not key:
            print("[!] API key entry missing in config file. Please re-run 'vt setup --apikey <KEY>' to initialize api key")
            sys.exit(1)
        return key
    
def remove_api_key() -> bool:
    try:
        if os.path.exists(p.CONFIG_PATH):
            os.remove(p.CONFIG_PATH)
            print("[✓] API key removed successfully.")
            return True
        else:
            print("[!] No API key found to remove.")
            return False
    except Exception as e:
        print(f"[✗] Error removing API key: {e}")
        return False
    
def display_api_key() -> str:
    key = load_api_key()
    if not key:
        print("[!] No API key found.")
    else:
        masked = key[:6] + "*" * (len(key) - 10) + key[-4:]
        print(f"[*] Stored API key: {masked}")