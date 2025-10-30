#!/bin/bash

APP_NAME="VirusTotal-CLI"
VENV_DIR="$HOME/.vtcli"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "❌ Cannot detect Linux Distro. Exiting..."
    exit 1
fi

DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')

if [[ "$DISTRO" =~ (ubuntu|debian|kali) ]]; then
    PKG_MGR="apt"
    INSTALL_CMD="sudo apt install -y"
    UPDATE_CMD="sudo apt update -y"
elif [[ "$DISTRO" =~ (arch|manjaro|endeavouros|garuda|arcolinux) ]]; then
    PKG_MGR="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
    UPDATE_CMD="sudo pacman -Syu --noconfirm"
else
    echo "⚠ Unsupported distribution: $DISTRO"
    echo "This installer supports only Debian/Ubuntu/Kali and Arch-based systems."
    exit 1
fi

echo "✅ Detected: $PRETTY_NAME"

echo "📦 Installing Python and required packages..."
$UPDATE_CMD

if [ "$PKG_MGR" = "apt" ]; then
    $INSTALL_CMD python3 python3-pip python3-venv git
elif [ "$PKG_MGR" = "pacman" ]; thens
    $INSTALL_CMD python python-pip git
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "🧱 Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR" 2>/dev/null || python -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"

if [ -f "requirements.txt" ]; then
    echo "📦 Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "⚠ No requirements.txt found, skipping dependency installation."
fi

if [ -f "main.py" ]; then
    echo "⚙ Setting up global command 'vt'..."
    cat <<EOF > vt
#!/usr/bin/env bash
cd "$(pwd)"
source "$VENV_DIR/bin/activate"
python3 main.py "\$@"
EOF

    chmod +x vt
    sudo mv vt /usr/local/bin/vt
    echo "✅ Installed global command: vt"
else
    echo "⚠ main.py not found, skipping vt command setup."
fi

echo ""
echo "🎉 $APP_NAME successfully installed!"
echo "Run it using:  vt --help"
echo ""