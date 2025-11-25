import os
import json
import sys
from data.api_constants import Paths as p

class KeyHelper():
    def __init__(self):
        self.config_path = p.CONFIG_PATH
        self.api_key_entry = p.API_KEY_ENTRY

    def save_api_key(self, key:str):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

        with open(self.config_path, "w", encoding='utf-8') as f:
            json.dump({self.api_key_entry: key}, f)
        print("[✓] API key saved successfully.")

    def load_api_key(self) -> str:
        if not os.path.exists(self.config_path):
            print("[!] API key not found. Please run 'vt setup --apikey <APIKEY>' first.")
            sys.exit(1)

        with open(self.config_path, "r", encoding='utf-8') as f:
            key = json.load(f).get(self.api_key_entry)
            if not key:
                print("[!] API key entry missing in config file. Please re-run 'vt setup --apikey <KEY>' to initialize api key")
                sys.exit(1)
            return key

    def remove_api_key(self) -> bool:
        try:
            if os.path.exists(self.config_path):
                os.remove(self.config_path)
                print("[✓] API key removed successfully.")
                return True
            else:
                print("[!] No API key found to remove.")
                return False
        except Exception as e:
            print(f"[✗] Error removing API key: {e}")
            return False

    def display_api_key(self) -> str:
        key = self.load_api_key()
        if not key:
            print("[!] No API key found.")
        else:
            masked = key[:6] + "*" * (len(key) - 10) + key[-4:]
            print(f"[*] Stored API key: {masked}")