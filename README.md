<hr />

```bash
   █████   █████ ███████████              █████████  █████       █████
  ░░███   ░░███ ░█░░░███░░░█             ███░░░░░███░░███       ░░███ 
   ░███    ░███ ░   ░███  ░             ███     ░░░  ░███        ░███ 
   ░███    ░███     ░███     ██████████░███          ░███        ░███ 
   ░░███   ███      ░███    ░░░░░░░░░░ ░███          ░███        ░███ 
    ░░░█████░       ░███               ░░███     ███ ░███      █ ░███ 
      ░░███         █████               ░░█████████  ███████████ █████
       ░░░         ░░░░░                 ░░░░░░░░░  ░░░░░░░░░░░ ░░░░░ 
```
<hr />

# VirusTotal CLI Tool

[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)  
[![License](https://img.shields.io/badge/BSD-3-Clause)](LICENSE)

A **fast, modern and user-friendly** command-line interface for interacting with the **VirusTotal v3 API**.  
Designed for **security researchers**, **malware analysts**, and **DFIR / SOC** workflows — directly from the terminal.
Scan files/URLs, fetch intelligence for domains and IPs, inspect account quotas, and self-update with a single command.

---

## Features

- ✅ **API Key Management**  
  - `vt setup --apikey <API_KEY>`: Save your VirusTotal API key.  
  - `vt key show`: View your saved API key.  
  - `vt key remove [--force]`: Remove your API key with optional confirmation bypass.

- ✅ **File Operations**  
  - Scan files (`vt file scan <path>`).  
  - Retrieve reports (`vt file report <hash>`).  
  - Request rescan (`vt file rescan <hash>`).  
  - Supports large files (>32MB) using VirusTotal upload URLs.

- ✅ **URL Analysis**  
  - Scan URLs (`vt url scan <url>`).  
  - Retrieve URL reports (`vt url report <url_or_base64>`).

- ✅ **Domain & IP Intelligence**  
  - Query domains (`vt domain report <domain_name>`).  
  - Query IP addresses (`vt ip report <ip_address>`).

- ✅ **User Account Information**  
  - `vt account info`: Get account details (email, API key, quotas, privileges).  

- ✅ **Analysis Lookup**  
  - `vt analysis <id>`: Retrieve analysis details by ID.

- ✅ **Automatic Updates**  
  - `vt update`: Check for the latest version and update the CLI automatically.  
  - Handles Git detection and Python dependencies.

- ✅ **Cross-Platform Support**  
  - Works on Linux (Debian/Ubuntu/Kali/Arch) and Windows (PowerShell).

---

## Installation

### Linux (Debian/Ubuntu/Kali/Arch)


```bash
# Clone repository
git clone https://github.com/Soumyo001/VirusTotal-CLI.git
cd VirusTotal-CLI
chmod +x install.sh

# Run installer
./install.sh
```
> The installer will create a Python virtual environment, install all dependencies, and set up the CLI.

### Windows (PowerShell)

```powershell
# Clone repository
git clone https://github.com/Soumyo001/VirusTotal-CLI.git
cd VirusTotal-CLI

# Run PowerShell installer
powershell -Executionpolicy Bypass .\install.ps1
```

> Git must be installed and in PATH for the installer and update commands.

---

## Usage

### API Key Setup

```bash
vt setup --apikey <YOUR_API_KEY>          # Setup your VirusTotal API key
vt key show                              # Show stored API key
vt key remove                             # Remove API key with warning
vt key remove --force                      # Remove API key without warning
```

### File Operations

```bash
vt file scan <path_to_file> [--json]      # Scan a file
vt file report <hash> [--json]            # Get report by file hash
vt file rescan <hash> [--json]            # Request file rescan
```

### URL Operations

```bash
vt url scan <url> [--json]                # Scan a URL
vt url report <id_or_url> [--json]        # Get URL report by ID or raw URL
```

### Domain

```bash
vt domain report example.com
vt domain rescan example.com
```

### IP
```bash
vt ip report 8.8.8.8
vt ip rescan 8.8.8.8
```

### Account Info & Quotas

```bash
vt account info [--json]                  # Show account info
```

### Analysis Lookup

```bash
vt analysis <analysis_id> [--json]        # Get analysis details
```

### Update CLI

```bash
vt update
```

---

## Project Structure

```bash
VirusTotal-CLI/
│
├─ api/
│   ├─ __init__.py
│   └─ api_client.py              # Handles requests to VirusTotal API
│
├─ cli/
│   ├─ __init__.py
│   └─ cli.py                     # Main CLI command dispatcher
│
├─ data/
│   ├─ __init__.py
│   ├─ api_constants.py           # Endpoints, URLs, JSON response keys
│   └─ constants.py               # Banners, labels, and common messages
│
├─ utils/
│   ├─ __init__.py
│   ├─ helpers/
│   │  ├─ __init__.py
│   │  ├─ hash.py                 # File hashing helper
│   │  ├─ key_helper.py           # Local API key storage
│   │  ├─ url_to_vt_id_helper.py  # Converts URL → VT URL ID format
│   │  └─ printer_helper/
│   │     ├─ print_user.py
│   │     ├─ print_domain_helper.py
│   │     ├─ print_ip_helper.py
│   │     ├─ print_url_helper.py
│   │     └─ print_file_helper.py
│   │
│   └─ validators/
│      ├─ __init__.py
│      └─ url_validator.py        # Validates input URLs
│
├─ install.sh                     # Linux installer (Deb/Ubuntu/Kali/Arch)
├─ install.ps1                    # Windows installer (Coming soon)
├─ requirements.txt               # Python dependencies
├─ main.py                        # Program entry point
├─ VERSION                        # Current CLI version (used in auto-update)
└─ README.md
```

---
## Development

- Python 3.10+ required.
- Dependencies listed in `requirements.txt`.
- Recommended workflow: git clone → virtual environment → install dependencies.

```bash
python3 -m venv venv
source venv/bin/activate      # Linux
powershell -Executionpolicy Bypass ".\venv\Scripts\activate.ps1"     # Windows
pip install -r requirements.txt
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
    
2. Create a feature branch (`git checkout -b feature-name`).
    
3. Commit your changes (`git commit -m "Feature description"`).
    
4. Push the branch (`git push origin feature-name`).
    
5. Open a Pull Request.

---
## Roadmap / Future Work

- Windows installer and update support (complete PowerShell UX)

- Packaged executables (PyInstaller / MSI)

- Official PyPI package & Homebrew tap for easier install

- More VirusTotal endpoints (private collections, retrohunt, intelligence)

- CI: tests + release automation (GitHub Actions)

---

## **License**

This project is licensed under the **[BSD 3-Clause License](LICENSE)**. See LICENSE for details.