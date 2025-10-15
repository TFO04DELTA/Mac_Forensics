#!/usr/bin/env bash
# ---------------------------------------------------------------

# ---------------------------------------------------------------

set -e

echo "=== Mac Forensic GUI Installer ==="
echo "This script installs dependencies so the GUI can run."
echo "Run only with proper authorization."
echo

# 1. Check macOS version
sw_vers

# 2. Ensure Homebrew is installed
if ! command -v brew &>/dev/null; then
  echo "[*] Homebrew not found — installing..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
  echo "[*] Homebrew already installed."
fi

# 3. Install/Update Python3
if ! command -v python3 &>/dev/null; then
  echo "[*] Installing Python3 via Homebrew..."
  brew install python
else
  echo "[*] Python3 found: $(python3 --version)"
  echo "[*] Upgrading to latest..."
  brew upgrade python || true
fi

# 4. Install Tkinter dependencies explicitly
echo "[*] Installing Tkinter GUI dependencies..."
# Check if tcl-tk is already installed
if brew list tcl-tk &>/dev/null; then
  echo "[+] tcl-tk already installed."
else
  brew install tcl-tk
fi

# Link Tcl/Tk to Python’s site-packages (important for Homebrew builds)
echo "[*] Linking Tcl/Tk so Python can find it..."
PYTHON_PATH=$(brew --prefix python)
TCLTK_PATH=$(brew --prefix tcl-tk)

# Update environment variables in shell startup if missing
if ! grep -q "TCL_LIBRARY" ~/.zprofile 2>/dev/null; then
  {
    echo ""
    echo "# Added by Mac Forensic GUI installer"
    echo "export LDFLAGS=\"-L${TCLTK_PATH}/lib\""
    echo "export CPPFLAGS=\"-I${TCLTK_PATH}/include\""
    echo "export PKG_CONFIG_PATH=\"${TCLTK_PATH}/lib/pkgconfig\""
    echo "export PATH=\"${PYTHON_PATH}/bin:\$PATH\""
    echo "export TK_SILENCE_DEPRECATION=1"
  } >> ~/.zprofile
  echo "[*] Updated ~/.zprofile with Tcl/Tk and Python paths."
else
  echo "[*] Tcl/Tk environment already configured."
fi

# 5. Verify tkinter import
echo "[*] Verifying Tkinter..."
if python3 - <<'EOF'
try:
    import tkinter
    print("Tkinter OK (version:", tkinter.TkVersion, ")")
except Exception as e:
    raise SystemExit("Tkinter test failed: " + str(e))
EOF
then
  echo "[+] Tkinter functional."
else
  echo "[!] Tkinter test failed — trying to reinstall python-tk."
  brew reinstall python-tk || echo "[!] python-tk formula not available; ensure tcl-tk is linked properly."
fi

# 6. Create default forensic output directory
OUTDIR="/Users/forensics"
echo "[*] Creating ${OUTDIR}..."
sudo mkdir -p "$OUTDIR"
sudo chown "$(whoami)" "$OUTDIR"

# 7. Remind user about Full Disk Access
echo
echo "--------------------------------------------------------------"
echo " ACTION REQUIRED:"
echo "  • Open System Settings → Privacy & Security → Full Disk Access"
echo "  • Add the Terminal app (and iTerm if you use it)."
echo "  • Restart Terminal afterward."
echo "--------------------------------------------------------------"
echo

# 8. Make the forensic script executable
if [ -f "mac_forensic_gui.py" ]; then
  chmod +x mac_forensic_gui.py
  echo "[*] Made mac_forensic_gui.py executable."
else
  echo "[!] mac_forensic_gui.py not found in current directory."
fi

# 9. Final summary
echo
echo "✅ Installation complete."
echo "Restart Terminal for environment variables to take effect."
echo
echo "To launch the GUI, run:"
echo "   sudo python3 mac_forensic_gui.py"
echo
