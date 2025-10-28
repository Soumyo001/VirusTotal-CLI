import argparse, sys
from data.api_constants import Paths as p
from data.constants import BANNER
from utils.helpers.key_helper import save_api_key, load_api_key, remove_api_key, display_api_key
from utils.helpers.hash import compute_hashes
from utils.helpers.url_to_vt_id_helper import url_to_vt_id
from utils.helpers.printer_helper.print_file_helper import print_file_details
from utils.helpers.printer_helper.print_url_helper import print_url_details
from utils.validators.url_validator import validate_url
from api.api_client import VirusTotalClient

class VTCLI:
    def __init__(self):
        self.parser = self._setup_cli()

    def _setup_cli(self):
        parser = argparse.ArgumentParser(
            prog='vt',
            description="VirusTotal CLI Tool — Access VirusTotal API from terminal"
        )

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
        url_report.add_argument("--json", action="store_true")

        # Domain related command
        domain_parser = subparsers.add_parser("domain", help="Domain intelligence")
        domain_parser.add_argument("domain_name", help="Domain name")
        domain_parser.add_argument("--json", action="store_true")

        # IP related command
        ip_parser = subparsers.add_parser("ip", help="IP intelligence")
        ip_parser.add_argument("ip_address", help="IP address")
        ip_parser.add_argument("--json", action="store_true")

        # user account related command
        account_parser = subparsers.add_parser("account", help="Current user account related operations")
        account_sub = account_parser.add_subparsers(dest="action", help="Current user account related actions")

        # user account info
        account_info = account_sub.add_parser("info", help="Get current user info")
        account_info.add_argument("--json", action="store_true")

        # user account quota
        account_quota = account_sub.add_parser("quota", help="Show API usage/quota info")
        account_quota.add_argument("--json", action="store_true")

        # get analysis
        analysis_parser = subparsers.add_parser("analysis", help="Get file/URL analysis result")
        analysis_sub = analysis_parser.add_subparsers(dest="action", help="Analysis for file/URL")

        file_analysis = analysis_sub.add_parser("file", help="Get file analysis result")
        file_analysis.add_argument("id", help="File Analysis ID")
        file_analysis.add_argument("--json", action="store_true")

        url_analysis = analysis_sub.add_parser("url", help="Get URL analysis results")
        url_analysis.add_argument("id", help="URL Analysis ID")
        url_analysis.add_argument("--json", action="store_true")

        return parser

    def run(self):
        args = self.parser.parse_args()

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

        if args.command == "file":
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
                response = vt.request_rescan(args.hash)
                print_file_details(response, args.json)

        elif args.command == "url":
            if args.action == "scan":
                # print(f"url scan command: {args.url} {args.json}")
                response = vt.scan_url(args.url)
                print_url_details(response, args.json, is_url=True)
            elif args.action == "report":
                source = args.id_or_url
                if validate_url(source):
                    vt_id = url_to_vt_id(source)
                    print(f"[→] Encoded URL to id: {vt_id}")
                else: vt_id = source
                # print(f"url scan report: {vt_id} {args.json}")
                response = vt.get_url_report(vt_id)
                print_url_details(response, args.json, is_url=True)

        elif args.command == "domain":
            print(f"domain command: {args.domain_name} {args.json}")

        elif args.command == "ip":
            print(f"IP command: {args.ip_address} {args.json}")

        elif args.command == "account":
            if args.action == "info":
                print(f"account info {args.json}")
            elif args.action == "quota":
                print(f"account quota {args.json}")

        elif args.command == "analysis":
            print(f"analysis command: {args.id} {args.json} {args.action}")
            response = vt.get_analysis(args.id)
            if args.action == "file":
                print_file_details(response, args.json)
            elif args.action == "url":
                print_url_details(response, args.json)

        else: self.parser.print_help()
