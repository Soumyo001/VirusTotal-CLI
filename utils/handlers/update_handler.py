import sys, os, subprocess, requests, shutil
from data.constants import VERSION_LINK

class UpdateHandler:
    
    def __init__(self, project_root, version):
        self.project_root = project_root
        self.current_version = version
    
    def check_for_updates(self, display_update_message=False):
        try:
            resp = requests.get(VERSION_LINK, timeout=3)
            latest_version = resp.text.strip()
            if latest_version != self.current_version:
                if display_update_message:
                    print(f"\n[!] Update available: {latest_version} (You have {self.current_version})")
                    print("    Run: vt update\n")
                return True
            return False
        except requests.RequestException as e:
            print(f"[!] Could not check for updates: {e}")
            return None

    def handle_update(self):
        if shutil.which("git") is None:
            print("[!] Git is not installed or not in PATH.")
            print("    Please install Git to use the update command:")
            print("    Ubuntu/Debian: sudo apt install git")
            print("    Arch/Manjaro: sudo pacman -S git")
            print("    Windows: https://git-scm.com/download/win")
            return
        
        update_status = self.check_for_updates(display_update_message=False)
        if update_status is True:
            print("[*] Update available")
        elif update_status is False:
            print("[✓] Already up to date")
            return
        else: 
            print("[!] Update check failed, could not verify latest version.")
            return

        print("[*] Updating vt-cli...")

        repo_dir = self.project_root
        if not repo_dir:
            print("[!] Failed to get project root directory. Update Failed.")
            return

        # get latest git commit
        try:
            subprocess.check_call(["git", "-C", repo_dir, "pull", "--rebase"])
            print("[✓] Source code updated.")
        except subprocess.CalledProcessError:
            print("[!] Update failed: Could not pull latest code.")
            print("    → Ensure this is a git clone, not a downloaded zip.")
            return

        # 2. Update dependencies
        req_file = os.path.join(repo_dir, "requirements.txt")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_file])
            print("[✓] Dependencies updated.")
        except subprocess.CalledProcessError:
            print("[!] Dependency update encountered issues (continuing...).")

        print("\n[✓] vt-cli is now up to date.\n")