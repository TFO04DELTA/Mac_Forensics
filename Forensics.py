#!/usr/bin/env python3
"""
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

"""
import os
import sys
import subprocess
import shutil
import hashlib
import tarfile
import tempfile
import time
import getpass
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# -------- Configuration: artifacts to collect (logical collection) --------
ARTIFACTS = [
    # tuples of (description, path, is_shell)
    ("Unified log (log collect)", None, "log_collect"),
    ("Unified log (last 21d)", None, "log_show_21d"),
    ("User Library", "{HOME}/Library", False),
    ("iCloud Mobile Documents", "{HOME}/Library/Mobile Documents", False),
    ("Messages DB", "{HOME}/Library/Messages/chat.db", False),
    ("Messages Attachments", "{HOME}/Library/Messages/Attachments", False),
    ("Safari", "{HOME}/Library/Safari", False),
    ("TCC DB (privacy permissions)", "{HOME}/Library/Application Support/com.apple.TCC/TCC.db", False),
    ("~/Library/Accounts", "{HOME}/Library/Accounts", False),
    ("System /var/log", "/var/log", False),
]

# -------------------- Helper functions --------------------

def log(msg):
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    state = f"[{now}] {msg}\n"
    app_text.insert(tk.END, state)
    app_text.see(tk.END)
    app_text.update()


def require_root_check():
    if os.geteuid() != 0:
        return False
    return True


def safe_mkdir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd, cwd=None, capture=False):
    """Run a shell command. Returns (returncode, stdout, stderr) if capture=True
    otherwise returns returncode."""
    try:
        if capture:
            res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
            return res.returncode, res.stdout, res.stderr
        else:
            res = subprocess.run(cmd, shell=True, cwd=cwd)
            return res.returncode
    except Exception as e:
        return 1, "", str(e)


def sha256_of_file(path: Path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_manifest(folder: Path, output_path: Path):
    with open(output_path, 'w') as mf:
        for root, dirs, files in os.walk(folder):
            for name in files:
                fpath = Path(root) / name
                try:
                    s = sha256_of_file(fpath)
                except Exception as e:
                    s = f"ERROR: {e}"
                mf.write(f"{s}  {str(fpath)}\n")

# -------------------- Collection logic --------------------

def perform_collection(case_dir: Path, target_user: str):
    """Performs logical collection according to ARTIFACTS into case_dir."""
    log(f"Starting collection into: {case_dir}")
    HOME = str(Path('/Users') / target_user)
    env = os.environ.copy()
    env['HOME'] = HOME

    for desc, path_tpl, mode in ARTIFACTS:
        try:
            log(f"Collecting: {desc}")
            if mode == 'log_collect':
                out_archive = case_dir / 'unified_logs.logarchive'
                # requires root
                rc = run_cmd(f"log collect --output '{out_archive}'")
                if rc == 0:
                    log(f"Collected unified logs -> {out_archive}")
                else:
                    log(f"log collect returned code {rc}")
                continue

            if mode == 'log_show_21d':
                out_file = case_dir / 'unified_log_21d.txt'
                # adjust macOS date flags if necessary; this uses BSD date -v-21d
                cmd = f"log show --start \"$(date -v-21d '+%Y-%m-%d %H:%M:%S')\" --info --debug > '{out_file}'"
                rc = run_cmd(cmd)
                if rc == 0:
                    log(f"Collected 21-day log -> {out_file}")
                else:
                    log(f"log show failed with code {rc}")
                continue

            # normal folder/file copy
            if path_tpl is None:
                log(f"Skipping unknown artifact {desc}")
                continue
            path = Path(path_tpl.format(HOME=HOME))
            dest = case_dir / 'usercopy' / path.relative_to('/')
            if path.exists():
                if path.is_dir():
                    log(f"Copying directory {path} to {dest}")
                    shutil.copytree(path, dest, dirs_exist_ok=True, copy_function=shutil.copy2)
                else:
                    safe_mkdir(dest.parent)
                    log(f"Copying file {path} to {dest}")
                    shutil.copy2(path, dest)
            else:
                log(f"Path not found: {path} (skipping)")
        except Exception as e:
            log(f"Error collecting {desc}: {e}")

    # Additional useful captures: system profiler, user list, mounts
    try:
        sp = case_dir / 'system_profiler.txt'
        run_cmd(f"system_profiler -detailLevel mini > '{sp}'")
        log(f"Saved system_profiler -> {sp}")
        who = case_dir / 'whoami_and_users.txt'
        run_cmd(f"whoami > '{who}'; dscl . list /Users >> '{who}'")
        log(f"Saved user list -> {who}")
    except Exception as e:
        log(f"Error collecting system info: {e}")

    # create manifest (sha256 of files in case_dir)
    try:
        manifest = case_dir / 'collection_hashes.txt'
        log("Generating SHA256 manifest (may take a while)...")
        sha256_manifest(case_dir, manifest)
        log(f"Manifest written -> {manifest}")
    except Exception as e:
        log(f"Error generating manifest: {e}")

    log("Collection complete.")

# -------------------- Packaging & Encryption --------------------

def package_and_encrypt(case_dir: Path, out_path: Path, passphrase: str):
    """Create a tar.gz of case_dir and encrypt with openssl AES-256-CBC.
    Returns path to encrypted file on success.
    """
    tmp_tar = out_path.with_suffix('.tar.gz')
    log(f"Creating compressed archive {tmp_tar}...")
    with tarfile.open(tmp_tar, 'w:gz') as tar:
        tar.add(case_dir, arcname=case_dir.name)
    log("Archive created.")

    enc_path = out_path
    log(f"Encrypting archive -> {enc_path} (AES-256-CBC)")
    # Use openssl to encrypt; passphrase provided by user
    cmd = f"openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -in '{tmp_tar}' -out '{enc_path}' -pass pass:{passphrase}"
    rc = run_cmd(cmd)
    if isinstance(rc, tuple):
        rc = rc[0]
    if rc == 0:
        log(f"Encrypted archive written -> {enc_path}")
        # remove tmp_tar
        try:
            os.remove(tmp_tar)
        except Exception:
            pass
        return enc_path
    else:
        log(f"Encryption failed (code {rc}). Archive retained at {tmp_tar}")
        return None

# -------------------- Remote upload (optional) --------------------

def upload_via_scp(enc_file: Path, remote_host: str, remote_user: str, remote_path: str, keyfile: str = None):
    """Upload the encrypted file using scp. If keyfile provided, use it; otherwise scp will prompt.
    Returns True on success.
    """
    log(f"Starting upload to {remote_user}@{remote_host}:{remote_path}")
    if keyfile:
        cmd = f"scp -i '{keyfile}' '{enc_file}' '{remote_user}@{remote_host}:{remote_path}'"
    else:
        cmd = f"scp '{enc_file}' '{remote_user}@{remote_host}:{remote_path}'"
    rc = run_cmd(cmd)
    if isinstance(rc, tuple):
        rc = rc[0]
    if rc == 0:
        log("Upload succeeded.")
        return True
    else:
        log(f"Upload failed with code {rc}")
        return False

# -------------------- GUI --------------------

def start_collection():
    if not require_root_check():
        messagebox.showwarning("Privilege required", "This script must be run as root (sudo) to collect all artifacts. Please re-run with sudo.")
        return
    target_user = user_entry.get().strip()
    if not target_user:
        messagebox.showerror("Missing user", "Please enter the short username (e.g., alice) to collect from.")
        return
    case_name = case_entry.get().strip() or (f"case_{time.strftime('%Y%m%d_%H%M%S')}")
    base_dir = Path(outdir_entry.get()).expanduser()
    case_dir = base_dir / case_name
    safe_mkdir(case_dir)
    log(f"Case directory: {case_dir}")
    perform_collection(case_dir, target_user)


def start_package():
    base_dir = Path(outdir_entry.get()).expanduser()
    case_name = case_entry.get().strip()
    if not case_name:
        messagebox.showerror("Missing case", "Please specify case name for packaging (should match collection).")
        return
    case_dir = base_dir / case_name
    if not case_dir.exists():
        messagebox.showerror("Not found", f"Case directory not found: {case_dir}")
        return
    outfile = filedialog.asksaveasfilename(title="Save encrypted archive as", defaultextension='.enc', initialfile=f"{case_name}.tar.gz.enc")
    if not outfile:
        return
    passphrase = simpledialog.askstring("Encryption passphrase", "Enter a passphrase to encrypt the archive (keep it safe).", show='*')
    if not passphrase:
        messagebox.showwarning("No passphrase", "Encryption cancelled - no passphrase provided.")
        return
    start_time = time.time()
    enc = package_and_encrypt(case_dir, Path(outfile), passphrase)
    if enc:
        elapsed = time.time() - start_time
        messagebox.showinfo("Done", f"Encrypted archive created: {enc}\nElapsed: {int(elapsed)}s")


def start_upload():
    enc_path = filedialog.askopenfilename(title="Select encrypted archive to upload")
    if not enc_path:
        return
    remote = simpledialog.askstring("Remote host", "Enter remote host (hostname or IP):")
    if not remote:
        return
    ruser = simpledialog.askstring("Remote user", "Enter remote username:")
    if not ruser:
        return
    rpath = simpledialog.askstring("Remote path", "Enter remote path (directory) to upload to:", initialvalue='.')
    key = filedialog.askopenfilename(title="Optional: select SSH private key (Cancel to skip)")
    upload_via_scp(Path(enc_path), remote, ruser, rpath, keyfile=(key if key else None))


def on_quit():
    if messagebox.askokcancel("Quit", "Quit the forensic collection GUI? Make sure you saved your logs."):
        root.destroy()


# -------------------- Main GUI layout --------------------
root = tk.Tk()
root.title("Mac Forensic Collector - Simple GUI")
root.geometry('900x600')

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

# Inputs: target user, case name, output dir
row = 0
ttk.Label(frame, text="Target short username:").grid(column=0, row=row, sticky=tk.W)
user_entry = ttk.Entry(frame, width=30)
user_entry.grid(column=1, row=row, sticky=tk.W)
user_entry.insert(0, getpass.getuser())

row += 1
ttk.Label(frame, text="Case name:").grid(column=0, row=row, sticky=tk.W)
case_entry = ttk.Entry(frame, width=40)
case_entry.grid(column=1, row=row, sticky=tk.W)

row += 1
ttk.Label(frame, text="Output directory:").grid(column=0, row=row, sticky=tk.W)
outdir_entry = ttk.Entry(frame, width=60)
outdir_entry.grid(column=1, row=row, sticky=tk.W)
outdir_entry.insert(0, str(Path('/Users/forensics').expanduser()))
btn_out = ttk.Button(frame, text="Browse", command=lambda: outdir_entry.insert(0, filedialog.askdirectory()))
btn_out.grid(column=2, row=row, sticky=tk.W)

row += 1
btn_collect = ttk.Button(frame, text="Start Collection (requires sudo)", command=start_collection)
btn_collect.grid(column=0, row=row, pady=8)
btn_package = ttk.Button(frame, text="Package & Encrypt", command=start_package)
btn_package.grid(column=1, row=row, pady=8)
btn_upload = ttk.Button(frame, text="Upload Encrypted Archive (scp)", command=start_upload)
btn_upload.grid(column=2, row=row, pady=8)

row += 1
sep = ttk.Separator(frame, orient='horizontal')
sep.grid(column=0, row=row, columnspan=3, sticky='ew', pady=8)

row += 1
# Log text area
app_text = tk.Text(frame, wrap='word', height=20)
app_text.grid(column=0, row=row, columnspan=3, sticky='nsew')
frame.rowconfigure(row, weight=1)
frame.columnconfigure(1, weight=1)

row += 1
btn_quit = ttk.Button(frame, text="Quit", command=on_quit)
btn_quit.grid(column=2, row=row, sticky=tk.E)

# Initial instructions in log area
app_text.insert(tk.END, "Mac Forensic Collector - log window\nEnsure you run this with sudo: sudo python3 mac_forensic_gui.py\nOnly run with explicit authorization.\n\n")

root.protocol("WM_DELETE_WINDOW", on_quit)

# If invoked directly, run the GUI mainloop
if __name__ == '__main__':
    root.mainloop()

# -------------------- End of file --------------------
