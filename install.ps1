$APP_NAME="VirusTotal-CLI"
$VENV_DIR="$env:userprofile\.vtcli"
$env:PSExecutionPolicyPreference = 'Bypass'

if (-not (Test-Path -Path $VENV_DIR -PathType Container)) {
    Write-Host "[+] Creating virtual environment directory: $VENV_DIR" -ForegroundColor Cyan
    New-Item -Path $VENV_DIR -ItemType Directory -Force
}


Write-Host "[*] Checking Python installation..." -ForegroundColor Cyan

if(-not (Get-Command python -ErrorAction SilentlyContinue)){
    Write-Host "[-] Python not found. Downloading Python..." -ForegroundColor Yellow
    Start-Process "https://www.python.org/downloads/windows/" -Wait
    Write-Host "Please install Python manually, then re-run this script." -ForegroundColor Yellow
    exit
}

$SCRIPT_PATH = $PSCommandPath
$DIR_PATH = [System.IO.Path]::GetDirectoryName($SCRIPT_PATH)
Write-Host "[+] Detected project directory: $PROJECT_DIR" -ForegroundColor Green

if( $DIR_PATH -ne $VENV_DIR ){
    Write-Host "[*] Moving project files to $VENV_DIR..." -ForegroundColor Cyan
    Get-ChildItem -Path $DIR_PATH -Force | Move-Item -Destination $VENV_DIR -Force
    Write-Host "[+] Files copied successfully." -ForegroundColor Green
    Set-Location -Path $VENV_DIR

    Write-Host "[*] Cleaning up old project directory..."
    Remove-Item -Path $DIR_PATH -Force -Recurse -ErrorAction SilentlyContinue
}

if( -not(Test-Path -Path "$VENV_DIR\venv" -PathType Container) ){
    Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Cyan
    try {
        python -m venv "$VENV_DIR\venv"
        Write-Host "[+] Virtual environment created." -ForegroundColor Green
    }
    catch {
        Write-Host "Error Creating python virtual environment: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# $activate_script = "$VENV_DIR\venv\Scripts\Activate.ps1"
# if (Test-Path -Path $activate_script -PathType Leaf) {
#     try {
#         Write-Host "[*] Activating virtual environment for script..." -ForegroundColor Cyan
#         . $activate_script
#     }catch {
#         Write-Host "Error Activating Virtual Environment: $($_.Exception.Message)" -ForegroundColor Red
#         exit 1
#     }
# } else {
#     Write-Host "Activate script not found at $activate_script" -ForegroundColor Red
#     exit 1
# }

$VENV_PYTHON = "$VENV_DIR\venv\Scripts\python.exe"

if (Test-Path -Path "$VENV_DIR\requirements.txt" -PathType Leaf) {
    try {
        Write-Host "[+] Installing dependencies..." -ForegroundColor Cyan
        & $VENV_PYTHON -m ensurepip --upgrade
        & $VENV_PYTHON -m pip install --upgrade pip
        & $VENV_PYTHON -m pip install -r requirements.txt
    }
    catch {
        Write-Host "[!] Error creating virtual environment or installing pip: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[-] requirements.txt not found. Skipping dependency installation." -ForegroundColor Yellow
}

Write-Host "[*] Setting up global command 'vt'..." -ForegroundColor Cyan
$shim = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\vt.cmd"

$shim_content = @'
@echo off
call %USERPROFILE%\.vtcli\venv\Scripts\activate.bat
python "%USERPROFILE%\.vtcli\main.py" %*
'@

$shim_content | Out-File $shim -Encoding ASCII

Write-Host "[+] Installed global command: vt" -ForegroundColor Green
Write-Host ""
Write-Host "[+] $APP_NAME successfully installed!"
Write-Host "Run it using: vt --help"
Write-Host ""