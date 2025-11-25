import sys, os, subprocess, requests, shutil, json
from data.constants import VERSION_LINK
from data.api_constants import Paths
from rich.console import Console
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown

class UpdateHandler:
    
    def __init__(self, project_root, version):
        self.project_root = project_root
        self.current_version = version
        self.config_dir = os.path.dirname(Paths.CONFIG_PATH)
        self.last_seen_file = Paths.LAST_SEEN_FILE
        self.changelog_file = os.path.join(self.project_root, "data/CHANGELOG.txt")
    
    def _parse_version(self, v):
        return tuple(map(int, (v.split("."))))

    def check_for_updates(self, display_update_message=False):
        try:
            resp = requests.get(VERSION_LINK, timeout=3)
            latest_version = resp.text.strip()
            latest = self._parse_version(latest_version)
            current = self._parse_version(self.current_version)

            if latest > current:
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

        # Update dependencies
        req_file = os.path.join(repo_dir, "requirements.txt")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r", req_file])
            print("[✓] Dependencies updated.")
        except subprocess.CalledProcessError:
            print("[!] Dependency update encountered issues (continuing...).")

        print("\n[✓] vt-cli is now up to date.\nrun vt to see the changelog for once")

    def show_update_banner_once(self):
        console = Console()
        os.makedirs(self.config_dir, exist_ok=True)

        # Load last seen version
        last_seen_version = None
        if os.path.exists(self.last_seen_file):
            try:
                with open(self.last_seen_file, "r") as f:
                    data = json.load(f)
                    last_seen_version = data.get("version")
            except:
                pass

        if last_seen_version == self.current_version:
            return

        # Otherwise, show changelog
        if os.path.exists(self.changelog_file):
            console.print("\n")
            console.print(
                Panel(
                    f"[bold cyan]🎉 A New Update Has Been Installed! (v{self.current_version})[/bold cyan]",
                    border_style="bright_cyan",
                )
            )
            console.print("[bold white]Here's what's new:[/bold white]\n")

            try:
                with open(self.changelog_file, "r", encoding="utf-8") as f:
                    changelog_text = f.read()
                if changelog_text.strip().startswith("#") or "*" in changelog_text:
                    console.print(Markdown(changelog_text))
                else:
                    console.print(Panel(changelog_text, border_style="green"))
            except Exception as e:
                console.print(
                    Panel(
                        f"[bold red]⚠ Failed to load changelog[/bold red]\n{str(e)}",
                        border_style="red"
                    )
                )

            console.print("\n")

        # Save new version as last seen
        try:
            with open(self.last_seen_file, "w") as f:
                json.dump({"version": self.current_version}, f)
        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]⚠ Could not update last_seen.json[/bold red]\n{str(e)}\n\n"
                    f"Manually put version [cyan]{self.current_version}[/cyan] into:\n[bold white]{self.last_seen_file}[/bold white]",
                    border_style="red",
                )
            )