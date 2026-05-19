#!/usr/bin/env bash
# BlackWall — installation script (Linux / macOS)
set -e

VENV_DIR="blackwall-env"

echo "[*] Creating virtual environment: $VENV_DIR"
python3 -m venv "$VENV_DIR"

echo "[*] Activating virtual environment"
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "[*] Installing dependencies"
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[✓] Installation complete."
echo "    To start BlackWall:"
echo "      source $VENV_DIR/bin/activate"
echo "      sudo -E streamlit run app.py"
