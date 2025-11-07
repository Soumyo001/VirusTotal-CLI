#!/bin/bash

APP_NAME="VirusTotal-CLI"
VENV_DIR="$HOME/.vtcli"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
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
echo ""

echo "📦 Installing Python and required tools..."
$UPDATE_CMD

if [ "$PKG_MGR" = "apt" ]; then
    $INSTALL_CMD python3 python3-pip python3-venv git
elif [ "$PKG_MGR" = "pacman" ]; then
    $INSTALL_CMD python python-pip git
fi

SCRIPT_PATH="$(realpath "$0")"
PROJECT_DIR="$(dirname "$SCRIPT_PATH")"
echo "📁 Detected project directory: $PROJECT_DIR"

if [ ! -d "$VENV_DIR" ]; then
    echo "🧱 Creating virtual environment directory: $VENV_DIR"
    mkdir -p "$VENV_DIR"
fi

if [ "$PROJECT_DIR" = "$VENV_DIR" ]; then
    echo "⚠ Project already in $VENV_DIR — skipping move."
else
    echo "📦 Moving project files to $VENV_DIR..."
    rsync -a "$PROJECT_DIR/" "$VENV_DIR/"
    if [ $? -ne 0 ]; then
        echo "❌ Error: Failed to copy project files. Exiting without deleting original folder."
        exit 1
    fi
    cd "$VENV_DIR"
    echo "✅ Files copied successfully."

    echo "🧹 Cleaning up old project directory..."
    rm -rf "$PROJECT_DIR"
fi


if [ ! -d "$VENV_DIR/venv" ]; then
    echo "🧱 Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR/venv" 2>/dev/null || python -m venv "$VENV_DIR/venv"
else
    echo "Virtual environment already exists at $VENV_DIR"
fi



source "$VENV_DIR/venv/bin/activate" || {
    echo "❌ Failed to activate virtual environment."
    exit 1
}

if [ -f "$VENV_DIR/requirements.txt" ]; then
    echo "📦 Installing Python dependencies..."
    pip install --upgrade pip setuptools wheel
    pip install -r "$VENV_DIR/requirements.txt"
else
    echo "⚠ No requirements.txt found, skipping dependency installation."
fi

BASH_PATH=$(which bash)

if [ -f "$VENV_DIR/main.py" ]; then
    echo "⚙ Setting up global command 'vt'..."
    cat <<EOF > vt
#!$BASH_PATH
source "$VENV_DIR/venv/bin/activate"
python3 "$VENV_DIR/main.py" "\$@"
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