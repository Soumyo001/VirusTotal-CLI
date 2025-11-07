import argparse, sys, os, subprocess, requests, shutil
from data.api_constants import Paths as p
from data.constants import BANNER, VERSION_LINK
from cli import __version__
from utils.helpers.key_helper import save_api_key, load_api_key, remove_api_key, display_api_key
from utils.helpers.hash import compute_hashes
from utils.helpers.url_to_vt_id_helper import url_to_vt_id
from utils.helpers.printer_helper.print_file_helper import print_file_details
from utils.helpers.printer_helper.print_url_helper import print_url_details
from utils.helpers.printer_helper.print_domain_helper import print_domain_details
from utils.helpers.printer_helper.print_ip_helper import print_ip_details
from utils.helpers.printer_helper.print_user import print_user_details 
from utils.validators.url_validator import validate_url
from api.api_client import VirusTotalClient

class VTCLI:
    def __init__(self):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._parser = self._setup_cli()

    def _check_for_updates(self, current_version, inline=False):
        try:
            resp = requests.get(VERSION_LINK, timeout=3)
            latest_version = resp.text.strip()
            if latest_version != current_version:
                if inline:
                    print(f"\n[!] Update available: {latest_version} (You have {current_version})")
                    print("    Run: vt update\n")
                return True
            return False
        except requests.RequestException as e:
            print(f"[!] Could not check for updates: {e}")
            return None

    def _handle_update(self):
        if shutil.which("git") is None:
            print("[!] Git is not installed or not in PATH.")
            print("    Please install Git to use the update command:")
            print("    Ubuntu/Debian: sudo apt install git")
            print("    Arch/Manjaro: sudo pacman -S git")
            print("    Windows: https://git-scm.com/download/win")
            return
        
        update_status = self._check_for_updates(__version__, inline=False)
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

    def _setup_cli(self):
        parser = argparse.ArgumentParser(
            prog='vt',
            description="VirusTotal CLI Tool — Access VirusTotal API from terminal"
        )
        parser.add_argument("-v", "--version", action="version", version=f"VirusTotal-CLI {__version__}")
        subparsers = parser.add_subparsers(dest="command", help="Main command categories")

        # setup api key commands
        setup_parser = subparsers.add_parser("setup", help= "Setup your VirusTotal API key")
        setup_parser.add_argument("--apikey", required=True, help="Your VirusTotal API key")

        # api key commands
        key_parser = subparsers.add_parser("key", help="VirusTotal API KEY related operations")
        key_sub = key_parser.add_subparsers(dest="action", help="API KEY related actions")

        # remove api key
        remove_key_parser = key_sub.add_parser("remove", help="Remove VirusTotal APIKEY")
        remove_key_parser.add_argument("--force", action="store_true", help="Remove API Key without Warning")

        # show api key
        key_sub.add_parser("show", help="Show API KEY")

        # file commands
        file_parser = subparsers.add_parser("file", help="File-Related operations")
        file_sub = file_parser.add_subparsers(dest="action", help="File-Related actions")

        # scan file
        file_scan = file_sub.add_parser("scan", help="Scan a file")
        file_scan.add_argument("path", help="path to file")
        file_scan.add_argument("--json", action="store_true", help="Output raw JSON")

        # compute file hash
        file_hash = file_sub.add_parser("hash", help="Compute file hashes (SHA256/MD5/SHA1)")
        file_hash.add_argument("path", help="Path to the file")

        # get file report
        file_report = file_sub.add_parser("report", help="Get a file report by hash")
        file_report.add_argument("hash", help="file hash (MD5/SHA256)")
        file_report.add_argument("--json", action="store_true")

        # request file rescan
        file_rescan = file_sub.add_parser("rescan", help="Request a file rescan by it's hash")
        file_rescan.add_argument("hash", help="file hash (MD5/SHA256)")
        file_rescan.add_argument("--json", action="store_true")

        # url commands
        url_parser = subparsers.add_parser("url", help="URL related operations")
        url_sub = url_parser.add_subparsers(dest="action", help="URL related actions")

        # url scan
        url_scan = url_sub.add_parser("scan", help="Scan a URL")
        url_scan.add_argument("url", help="url to scan")
        url_scan.add_argument("--json", action="store_true")

        # url report
        url_report = url_sub.add_parser(
            "report",
            help="Get URL scan report by ID (base64 form) OR pass a raw URL and it will be encoded"
        )
        url_report.add_argument("id_or_url", help="Safe Base64 encoded URL or raw")
        url_report.add_argument("--headers", action="store_true", help="Display all the headers")
        url_report.add_argument("--engines", action="store_true", help="Display all AV engines")
        url_report.add_argument("--json", action="store_true")

        # Domain related command
        domain_parser = subparsers.add_parser("domain", help="Domain intelligence")
        domain_sub = domain_parser.add_subparsers(dest="action", help="Domain related actions")

        domain_report = domain_sub.add_parser("report", help="Get a previously scanned domain report")
        domain_report.add_argument("domain_name", help="Domain name")
        domain_report.add_argument("--json", action="store_true")

        domain_rescan = domain_sub.add_parser("rescan", help="request domain rescan")
        domain_rescan.add_argument("domain_name")
        domain_rescan.add_argument("--json", action="store_true")

        # IP related command
        ip_parser = subparsers.add_parser("ip", help="IP intelligence")
        ip_sub = ip_parser.add_subparsers(dest="action", help="IP related commands")

        ip_report = ip_sub.add_parser("report", help="Get previously scanned IP report")
        ip_report.add_argument("ip_address", help="IP address")
        ip_report.add_argument("--json", action="store_true")

        ip_rescan = ip_sub.add_parser("rescan", help="Request IP rescan")
        ip_rescan.add_argument("ip_address")
        ip_rescan.add_argument("--json", action="store_true")

        # user account related command
        account_parser = subparsers.add_parser("account", help="Current user account related operations")
        account_sub = account_parser.add_subparsers(dest="action", help="Current user account related actions")

        # user account info
        account_info = account_sub.add_parser("info", help="Get current user info")
        account_info.add_argument("--json", action="store_true")

        # update tool
        subparsers.add_parser("update", help="Update the CLI tool to latest version")

        # get analysis
        analysis_parser = subparsers.add_parser("analysis", help="Get file/URL analysis result")
        analysis_sub = analysis_parser.add_subparsers(dest="action", help="Analysis for file/URL")

        file_analysis = analysis_sub.add_parser("file", help="Get file analysis result")
        file_analysis.add_argument("id", help="File Analysis ID")
        file_analysis.add_argument("--json", action="store_true")

        url_analysis = analysis_sub.add_parser("url", help="Get URL analysis results")
        url_analysis.add_argument("id", help="URL Analysis ID")
        url_analysis.add_argument("--headers", action="store_true")
        url_analysis.add_argument("--engines", action="store_true")
        url_analysis.add_argument("--json", action="store_true")

        domain_analysis = analysis_sub.add_parser("domain", help="Get Domain analysis results")
        domain_analysis.add_argument("id", help="Domain analysis ID")
        domain_analysis.add_argument("--json", action="store_true")

        ip_analysis = analysis_sub.add_parser("ip", help="Get IP analysis results")
        ip_analysis.add_argument("id", help="IP analysis ID")
        ip_analysis.add_argument("--json", action="store_true")

        return parser

    def run(self):
        args = self._parser.parse_args()
        self._check_for_updates(__version__, inline=True)

        if args.command == "setup":
            save_api_key(args.apikey)
            sys.exit(0)

        if args.command == "key":
            if args.action == "remove":
                if args.force: 
                    remove_api_key()
                else: 
                    confirm = input("⚠ Are you sure you want to remove your VirusTotal API key? [y/N]: ").strip().lower()
                    if confirm in ['y', 'yes']: 
                        remove_api_key()
                    else: 
                        print("✗ Operation cancelled. API key not removed.")
            elif args.action == "show":
                display_api_key()
            sys.exit(0)

        key = load_api_key()
        vt = VirusTotalClient(key)
        print(BANNER)

        if not key:
            print("[✗] Please set up your API key first using 'vt setup --apikey <your_key>'.")
            sys.exit(1)

        if args.command == "update":
            self._handle_update()

        elif args.command == "file":
            if args.action == "scan":
                # print(f"file scan command: {args.path} {args.json}")
                response = vt.scan_file(args.path)
                print_file_details(response, args.json)
            elif args.action == "hash":
                hashes = compute_hashes(args.path)
                print(f"SHA-256: {hashes["SHA256"]}\nMD5: {hashes["MD5"]}\nSHA-1: {hashes["SHA1"]}")
            elif args.action == "report":
                # print(f"file scan report: {args.hash} {args.json}")
                response = vt.get_file_report(args.hash)
                print_file_details(response, args.json)
            elif args.action == "rescan":
                # print(f"file rescan: {args.hash} {args.json}")
                response = vt.request_file_rescan(args.hash)
                print_file_details(response, args.json)

        elif args.command == "url":
            if args.action == "scan":
                # print(f"url scan command: {args.url} {args.json}")
                response = vt.scan_url(args.url)
                print_url_details(response, json_output=args.json)
            elif args.action == "report":
                source = args.id_or_url
                if validate_url(source):
                    vt_id = url_to_vt_id(source)
                    print(f"[→] Encoded URL to id: {vt_id}")
                else: vt_id = source
                # print(f"url scan report: {vt_id} {args.json}")
                response = vt.get_url_report(vt_id)
                print_url_details(response, json_output=args.json, show_headers=args.headers, show_engines=args.engines)

        elif args.command == "domain":
            # print(f"domain command: {args.domain_name} {args.json}")
            if args.action == "report":
                response = vt.get_domain_report(args.domain_name)
                print_domain_details(response, args.json)
            elif args.action == "rescan":
                response = vt.domain_rescan(args.domain_name)
                print_domain_details(response, args.json)

        elif args.command == "ip":
            # print(f"IP command: {args.ip_address} {args.json}")
            if args.action == "report":
                response = vt.get_ip_report(args.ip_address)
                print_ip_details(response, json_output=args.json)
            elif args.action == "rescan":
                response = vt.ip_rescan(args.ip_address)
                print_ip_details(response, json_output=args.json)

        elif args.command == "account":
            if args.action == "info":
                response = vt.get_user_info()
                print_user_details(response, args.json)

        elif args.command == "analysis":
            # print(f"analysis command: {args.id} {args.json} {args.action}")
            response = vt.get_analysis(args.id)
            if args.action == "file":
                print_file_details(response, json_output=args.json)
            elif args.action == "url":
                print_url_details(response, json_output=args.json, show_headers=args.headers, show_engines=args.engines)
            elif args.action == "domain":
                print_domain_details(response, json_output=args.json)
            elif args.action == "ip":
                print_ip_details(response, json_output=args.json)

        else: self._parser.print_help()
