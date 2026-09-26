import getpass

USERNAME = getpass.getuser()

BANNER = r"""
 █████   █████ ███████████              █████████  █████       █████
░░███   ░░███ ░█░░░███░░░█             ███░░░░░███░░███       ░░███ 
 ░███    ░███ ░   ░███  ░             ███     ░░░  ░███        ░███ 
 ░███    ░███     ░███     ██████████░███          ░███        ░███ 
 ░░███   ███      ░███    ░░░░░░░░░░ ░███          ░███        ░███ 
  ░░░█████░       ░███               ░░███     ███ ░███      █ ░███ 
    ░░███         █████               ░░█████████  ███████████ █████
     ░░░         ░░░░░                 ░░░░░░░░░  ░░░░░░░░░░░ ░░░░░ 

                          By defalt4o4 - Follow the debugger's path!

"""

HEADER = f"[~] {USERNAME}@vtcli $ "

HELP_MENU = """
COMMANDS
  setup --apikey <API_KEY>        Save your VirusTotal API key
  key show                        Display the stored API key (masked)
  key remove [--force]            Delete the stored API key

  file scan <PATH>                Upload and scan a file
  file hash <PATH>                Compute SHA256/MD5/SHA1 locally (no API call)
  file report <HASH>              Fetch an existing file report
  file rescan <HASH>              Request a fresh scan of a known file
  file trace <HASH>               Show the file's sandbox behaviour

  url scan <URL>                  Submit a URL for analysis
  url report <URL|BASE64_ID>      Fetch a URL report (raw URLs are auto-encoded)

  domain report <DOMAIN>          Fetch domain intelligence
  domain rescan <DOMAIN>          Request a fresh domain scan

  ip report <IP>                  Fetch IP intelligence
  ip rescan <IP>                  Request a fresh IP scan
  ip resolve [URL|DOMAIN]         Resolve a host to IPs, then report on each
                                    --self    report on your own public IP
                                    --ipv6    include IPv6 addresses

  account info                    Show your account profile and quota
  analysis {file|url|domain|ip} <ID>
                                  Fetch a previously queued analysis result
  update                          Update VirusTotal-CLI to the latest version

OUTPUT FLAGS
  --json                          Print the raw API response
  --all                           Do not truncate  (file report, file trace)
  --headers                       Show all HTTP headers  (url report, analysis url)
  --engines                       Show every AV engine verdict  (url report, analysis url)

EXAMPLES
  vt setup --apikey <API_KEY>
  vt file report 44d88612fea8a8f36de82e1278abb02f
  vt url scan https://example.com
  vt domain report example.com
  vt ip resolve --self
  vt analysis file <ANALYSIS_ID>

Run 'vt <command> --help' or 'vt <command> <action> --help' for full options.
"""
VERSION_LINK = "https://github.com/Soumyo001/VirusTotal-CLI/raw/refs/heads/main/version.txt"