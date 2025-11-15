import requests, os, sys
from data.api_constants import Paths as p, FileAnalysis as fa

class VirusTotalClient():
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

    # ----------------- FILE SCAN -----------------
    def scan_file(self, file_path: str):
        if not os.path.exists(file_path):
            return {"error": {"code": "File not found", "message": "File does not exist"}}
        
        file_size = os.path.getsize(file_path)
        max_regular = 32 * 1024 * 1024
        max_large = 650 * 1024 * 1024

        print(f"[+] File: {os.path.basename(file_path)} ({file_size / (1024*1024):.2f} MB)")

        if file_size <= max_regular:
            with open(file_path, "rb") as f:
                files = {"file" : (os.path.basename(file_path), f)}
                response = requests.post(f"{p.BASE_URL}/files", headers=self.headers, files=files)
            return response.json()
        
        elif file_size > max_regular and file_size <= max_large:
            print("[!] Large file detected (> 32 MB).")
            print("[*] Requesting large file upload URL from VirusTotal...")

            response = requests.get(f"{p.BASE_URL}/files/upload_url", headers=self.headers)

            upload_info = response.json()
            upload_url = upload_info.get(fa.DATA, {})
            if not upload_url:
                return {"error": {"code": "Failed to get large file upload URL", "message": upload_info}}
            
            print("[✓] Upload URL received.")
            print("[*] Uploading large file to VirusTotal (this may take several minutes)...")

            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(upload_url, headers=self.headers, files=files)
            return response.json()
        else:
            return {"error": {"code": "Large File Error", "message": f"File too large ({file_size / (1024*1024):.2f} MB). Max allowed is 650 MB."}}
        
    def get_file_report(self, file_hash: str):
        response = requests.get(f"{p.BASE_URL}/files/{file_hash}", headers=self.headers)
        return response.json()
    
    def request_file_rescan(self, file_hash: str):
        response = requests.post(f"{p.BASE_URL}/files/{file_hash}/analyse", headers=self.headers)
        return response.json()
    
    def get_file_behaviour(self, file_hash: str):
        response = requests.get(f"{p.BASE_URL}/files/{file_hash}/behaviour_summary", headers=self.headers)
        return response.json()
    
    # ----------------- URL SCAN -----------------
    def scan_url(self, url: str):
        data = {"url": url}
        response = requests.post(f"{p.BASE_URL}/urls", data=data, headers=self.headers)
        return response.json()
    
    def get_url_report(self, url_id: str):
        response = requests.get(f"{p.BASE_URL}/urls/{url_id}", headers=self.headers)
        return response.json()

    # ----------------- DOMAIN SCAN -----------------
    def get_domain_report(self, domain: str):
        response = requests.get(f"{p.BASE_URL}/domains/{domain}", headers=self.headers)
        return response.json()
    
    def domain_rescan(self, domain: str):
        response = requests.post(f"{p.BASE_URL}/domains/{domain}/analyse", headers=self.headers)
        return response.json()
    
    # ----------------- IP SCAN -----------------
    def get_ip_report(self, ip: str):
        response = requests.get(f"{p.BASE_URL}/ip_addresses/{ip}", headers=self.headers)
        return response.json()
    
    def ip_rescan(self, ip: str):
        response = requests.post(f"{p.BASE_URL}/ip_addresses/{ip}/analyse", headers=self.headers)
        return response.json()

    # ----------------- ACCOUNT -----------------
    def get_user_info(self):
        resp = requests.get(f"{p.BASE_URL}/users/{self.api_key}", headers=self.headers)
        return resp.json()

    # ----------------- FILE/URL ANALYSIS REPORT -----------------
    def get_analysis(self, analysis_id: str):
        response = requests.get(f"{p.BASE_URL}/analyses/{analysis_id}", headers=self.headers)
        return response.json()