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

                          By Defalt4o4 - Follow the debugger's path!

"""

HEADER = f"[~] {USERNAME}@vtcli $ "

HELP_MENU = """
        [::] virustotal cli help menu [::]

            [+] Arguments
                [*] vt file scan <FILE_PATH>
                [*] vt file report <FILE_HASH>
                [*] vt file rescan <FILE_HASH>
                [*] vt analysis <ANALYSIS_ID>
                
                [*] vt url scan <SITE_NAME>
                [*] vt url report <SITE_NAME>
                [*] vt domain info <DOMAIN>
                [*] vt ip info <IP>

                [*] vt account info
                [*] vt account quota
"""
VERSION_LINK = "https://github.com/Soumyo001/VirusTotal-CLI/raw/refs/heads/main/version.txt"