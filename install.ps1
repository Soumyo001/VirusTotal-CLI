$APP_NAME="VirusTotal-CLI"
$VENV_DIR="$env:userprofile/.vtcli"

if (-not (Test-Path -Path $VENV_DIR -PathType Container)) {
    Write-Host "🧱 Creating virtual environment directory: $VENV_DIR" -ForegroundColor Cyan
    New-Item -Path $VENV_DIR -ItemType Directory -Force
}


Write-Host "🔍 Checking Python installation..." -ForegroundColor Cyan
$python = Get-Command python -ErrorAction SilentlyContinue

if(-not $python){
    Write-Host "⚠ Python not found. Downloading Python..." -ForegroundColor Yellow
    Start-Process "https://www.python.org/downloads/windows/" -Wait
    Write-Host "Please install Python manually, then re-run this script." -ForegroundColor Yellow
    exit
}

$SCRIPT_PATH = $PSCommandPath
$DIR_PATH = [System.IO.Path]::GetDirectoryName($SCRIPT_PATH)
Write-Host "📁 Detected project directory: $PROJECT_DIR" -ForegroundColor Green

if( $DIR_PATH -ne $VENV_DIR ){
    Write-Host "📦 Moving project files to $VENV_DIR..." -ForegroundColor Cyan
    Get-ChildItem -Path $DIR_PATH -Force | Where-Object {$_ -ne ".git"} | Move-Item -Destination $VENV_DIR -Force
    Write-Host "✅ Files copied successfully." -ForegroundColor Green
    Set-Location -Path $VENV_DIR

    Write-Host "🧹 Cleaning up old project directory..."
    Remove-Item -Path $DIR_PATH -Force -Recurse -ErrorAction SilentlyContinue
}

if( -not(Test-Path -Path "$VENV_DIR\venv" -PathType Container) ){
    Write-Host "🧱 Creating Python virtual environment..." -ForegroundColor Cyan
    try {
        python -m venv "$VENV_DIR\venv"
    }
    catch {
        Write-Host "Error Creating python virtual environment: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "🔧 Activating virtual environment..." -ForegroundColor Cyan
try {
    # powershell.exe -ExecutionPolicy Bypass -NoExit -Command "& '$VENV_DIR\venv\Scripts\activate.ps1'"
    powershell -ExecutionPolicy Bypass -Command ". '$VENV_DIR\venv\Scripts\activate.ps1'; pwsh"
} catch {
    Write-Host "Error Activating Virtual Environment: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if (Test-Path "requirements.txt") {
    Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
    pip install --upgrade pip
    pip install -r requirements.txt
} else {
    Write-Host "⚠ requirements.txt not found. Skipping dependency installation." -ForegroundColor Yellow
}

Write-Host "⚙ Setting up global command 'vt'..." -ForegroundColor Cyan
$shim = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\vt.cmd"

@"
@echo off
call $VENV_DIR\venv\Scripts\activate.bat
python "$VENV_DIR/main.py" %*
"@ | Out-File $shim -Encoding ASCII


Write-Host "✅ Installed global command: vt" -ForegroundColor Green
Write-Host ""
Write-Host "🎉 $APP_NAME successfully installed!"
Write-Host "Run it using: vt --help"
Write-Host ""