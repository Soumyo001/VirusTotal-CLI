Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$APP_NAME="VirusTotal-CLI"
$VENV_DIR="$env:userprofile\.vtcli"
$env:PSExecutionPolicyPreference = 'Bypass'

if (-not (Test-Path -Path $VENV_DIR -PathType Container)) {
    Write-Host "[+] Creating virtual environment directory: $VENV_DIR" -ForegroundColor Cyan
    New-Item -Path $VENV_DIR -ItemType Directory -Force
}


Write-Host "[*] Checking Python installation..." -ForegroundColor Cyan
$pythonFound = $false
if(Get-Command python -ErrorAction SilentlyContinue){
    try {
        python --version *> $null
        if($LASTEXITCODE -eq 0) { $pythonFound = $true }
    } catch { $pythonFound = $false }
}
if(-not($pythonFound)) {
    Write-Host "[-] Python not found. Downloading Python..." -ForegroundColor Yellow
    Start-Process "https://www.python.org/downloads/windows/" -Wait
    Write-Host "Please install Python manually, Add python.exe to PATH, then re-run this script." -ForegroundColor Yellow
    exit 1
}

$SCRIPT_PATH = $PSCommandPath
$DIR_PATH = [System.IO.Path]::GetDirectoryName($SCRIPT_PATH)
Write-Host "[+] Detected project directory: $DIR_PATH" -ForegroundColor Green

if( $DIR_PATH -ne $VENV_DIR ){
    if( -not (Test-Path "$DIR_PATH\main.py") -or -not (Test-Path "$DIR_PATH\version.txt") ){
        Write-Host "[-] $DIR_PATH does not look like a VirusTotal-CLI clone. Aborting." -ForegroundColor Red
        exit 1
    }
    Write-Host "[*] Copying project files to $VENV_DIR..." -ForegroundColor Cyan
    Copy-Item -Path "$DIR_PATH\*" -Destination $VENV_DIR -Recurse -Force
    Set-Location -Path $VENV_DIR
    Write-Host "[+] Files copied successfully." -ForegroundColor Green

    Write-Host "[*] Cleaning up old project directory..."
    $answer = Read-Host "[?] Remove the original clone at ${DIR_PATH}? (Y/n)"
    if( [string]::IsNullOrWhiteSpace($answer) -or $answer.Trim() -match '^(y|yes)$' ){
        Remove-Item -Path $DIR_PATH -Force -Recurse -ErrorAction SilentlyContinue
        if(Test-Path -Path $DIR_PATH -PathType Container) {
            Write-Host "[!] $DIR_PATH could not be fully removed - delete it manually." -ForegroundColor Yellow
        } else {
            Write-Host "[+] Removed $DIR_PATH." -ForegroundColor Green
        }
    } else {
        Write-Host "[i] Keeping $DIR_PATH." -ForegroundColor Yellow
    }
}

if( -not(Test-Path -Path "$VENV_DIR\venv" -PathType Container) ){
    Write-Host "[*] Creating Python virtual environment..." -ForegroundColor Cyan
    try {
        python -m venv "$VENV_DIR\venv"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[-] Failed to create virtual environment (exit $LASTEXITCODE)." -ForegroundColor Red
            exit 1
        }
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
if(-not(Test-Path $VENV_PYTHON -PathType Leaf)) {
    Write-Host "[-] Virtual environment python not found at $VENV_PYTHON" -ForegroundColor Red
    exit 1
}

if (Test-Path -Path "$VENV_DIR\requirements.txt" -PathType Leaf) {
    try {
        Write-Host "[+] Installing dependencies..." -ForegroundColor Cyan
        & $VENV_PYTHON -m ensurepip --upgrade
        & $VENV_PYTHON -m pip install --upgrade pip
        & $VENV_PYTHON -m pip install -r "$VENV_DIR\requirements.txt"
        if($LASTEXITCODE -ne 0) {
            Write-Host "[-] Dependency installation failed (exit $LASTEXITCODE)." -ForegroundColor Red
            exit 1
        }
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
$shimDir = [System.IO.Path]::GetDirectoryName($shim)

if(-not(Test-Path $shimDir -PathType Container)) {
    Write-Host "[!] $shimDir not found. Creating directory..." -ForegroundColor Yellow
    New-Item -Path $shimDir -ItemType Directory -Force
}

$shim_content = @'
@echo off
call %USERPROFILE%\.vtcli\venv\Scripts\activate.bat
python "%USERPROFILE%\.vtcli\main.py" %*
'@

try {
    $shim_content | Out-File $shim -Encoding ASCII -ErrorAction Stop
    Write-Host "[+] Installed global command: vt" -ForegroundColor Green
}
catch {
    Write-Host "[-] Failed to write shim to $shim : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[+] $APP_NAME successfully installed!"
Write-Host "Run it using: vt --help"
Write-Host ""