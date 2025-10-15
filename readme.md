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
