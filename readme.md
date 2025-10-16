install_mac_forensic_gui.sh
Purpose: one-time setup script to ensure prerequisites for
mac_forensic_gui.py are met on macOS.
Includes explicit Homebrew Tkinter setup.


--------------------------------------------------------------------------------


mac_forensic_gui.py

Simple, self-contained GUI tool (Tkinter) to perform an investigator-authorized
logical collection from a macOS user account, package the results into an
encrypted archive, and optionally upload it to a remote SFTP/SCP endpoint.

Design goals:
- No special commercial tools required (uses standard macOS command-line tools).
- Minimal, clear UI: Start collection, Package & Encrypt, Optional Upload.
- Detailed logging of actions + SHA256 manifest.
- Safe defaults: requires operator to run with sudo (many collection steps need root).

WARNING / legal: Only run this on devices you are explicitly authorized to collect from.
Document consent, date/time, and chain-of-custody. This tool does not bypass any
passwords, FileVault, or Apple protections. It only collects locally-available
artifacts.

Run:
  sudo python3 mac_forensic_gui.py

If you cannot run with sudo, run the CLI variant at the bottom or re-run the
script with the required privileges. The GUI will check for root and warn.
----------------------------------------------------------------------------------


forensic_log_parser.py

Standalone Tkinter GUI to stream-parse many large log files for iCloud / AppleID / sync
and related suspicious events, correlate events into sessions, flag HIGH_PRIORITY sessions,
and export matches + sessions with SHA256 manifest integration.

Usage:
    python3 forensic_log_parser.py

Notes:
 - Operates on copies (do not modify original evidence).
 - Designed to be memory-efficient when scanning file-by-file, though matches are stored
   for GUI interaction; very large numbers of matches may increase memory usage.
 - collection_hashes.txt (manifest) is optional but recommended — the script will look
   for it in the selected folder and attempt to match evidence file paths to include SHA256.
