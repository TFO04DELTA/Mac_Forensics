#!/usr/bin/env python3
from __future__ import annotations
import os
import re
import csv
import threading
import time
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# ---------------- Configuration & Rules (iCloud-focused) ----------------
# Each rule is: (label, regex pattern, score (0-100), description)
RULES = [
    ("APPLEID_SIGNIN", r"\b(sign in|signed in|signed-in|signed in to|appleid|apple id|appleid\.apple\.com|icloud\.com/signin)\b", 85,
     "Potential Apple ID / sign-in / web signin related"),
    ("ACCOUNT_CHANGE", r"\b(password change|recovery key|recovery key created|trusted phone|trusted device|added phone|removed phone|recovery contact|two-step|two-factor)\b", 95,
     "Possible account setting change"),
    ("BIRD_SYNC", r"\bbird\b.*\b(download|upload|sync|push|pull|received|transferred|item)\b", 90, "iCloud 'bird' sync activity"),
    ("CLOUDD", r"\bcloudd\b", 75, "CloudKit daemon activity"),
    ("ACCOUNTD", r"\baccountd\b", 75, "accountd (Apple ID/account) activity"),
    ("APS_SERVICE", r"\bapsd\b|\bApplePushService\b", 70, "Apple Push Service (push token refresh)"),
    ("TCC_CHANGE", r"\bTCC\b|\bcom\.apple\.TCC\b|\bPrivacy.*access\b|\bkTCCService\b", 80, "Privacy/TCC permission change"),
    ("FILE_DELETE", r"\b(delete|deleted|removed|unlink(ed)?|rm\b|moved to trash|trash item)\b", 90, "File deletion or removal"),
    ("LOG_ERASE", r"\b(log erase|log collect|log remove|clear logs|system log cleared)\b", 95, "Possible log cleanup or collection"),
    ("NETWORK_UPLOAD", r"\b(scp|rsync|curl|ftp|wget|POST /|upload|PUT /|aws s3|s3.amazonaws.com)\b", 88, "Possible network upload"),
    ("ARCHIVE_CREATE", r"\b(zip|\.tar\.gz|\.tgz|\.7z|\.rar|created archive|packaged|compressed)\b", 80, "Archive created (possible bundling)"),
    ("LAUNCHD_CHANGE", r"\b(launchd|LaunchAgent|LaunchDaemon|plist|com\..*\.plist)\b", 70, "Possible persistence/launcher created"),
]

# Context sizes
PRE_CONTEXT = 12
POST_CONTEXT = 8

# Session correlation defaults
SESSION_WINDOW_SEC = 600     # 10 minutes
SESSION_MIN_EVENTS = 4
SESSION_HIGH_SCORE = 80

# Output filenames (relative to selected folder)
MATCHES_CSV = "matches_export.csv"
SESSIONS_CSV = "sessions_summary.csv"

# Timestamp regex (attempt to capture common formats at line start)
TIMESTAMP_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+\-]\d{2}:?\d{2})?)'
)

# ---------------- Utility functions ----------------
def try_extract_timestamp(line: str):
    """Try to extract a timestamp at the start of a log line and normalize to ISO UTC.
    Returns ISO8601 UTC string or None."""
    m = TIMESTAMP_RE.match(line)
    if not m:
        return None
    ts = m.group("ts")
    # Normalize timezone like +0000 to +00:00
    try:
        # handle timezone formats
        if re.search(r'[+\-]\d{4}$', ts):
            ts = ts[:-5] + ts[-5:-2] + ":" + ts[-2:]
        # Replace space ' ' between date and time with 'T' for iso parsing
        ts = ts.replace(" ", "T")
        dt = datetime.fromisoformat(ts)
        dt_utc = dt.astimezone(timezone.utc)
        return dt_utc.isoformat()
    except Exception:
        return None

def current_iso_utc():
    return datetime.now(timezone.utc).isoformat()

# ---------------- Manifest loader ----------------
def load_hash_manifest(manifest_path: Path):
    """
    Load collection_hashes.txt or similar manifest.
    Accepts many common formats; attempts to map filenames (basename and relative path) to hash.
    Returns dict: { normalized_path_or_basename: sha256 }
    """
    hashes = {}
    if not manifest_path or not manifest_path.exists():
        return hashes
    try:
        with manifest_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Try formats like: "<sha256>  /abs/path/to/file"
                m = re.match(r'([a-fA-F0-9]{64})\s+\*?(.+)', line)
                if m:
                    h = m.group(1).lower()
                    path = m.group(2).strip()
                    # store by basename and by normalized relative path
                    hashes[os.path.basename(path)] = h
                    hashes[path] = h
                    continue
                # Try formats like: "SHA256 (file) = hash"
                m2 = re.match(r'.*\((.+)\)\s*=\s*([a-fA-F0-9]{64})', line)
                if m2:
                    path = m2.group(1).strip()
                    h = m2.group(2).lower()
                    hashes[os.path.basename(path)] = h
                    hashes[path] = h
                    continue
                # Try "hash filename"
                parts = line.split()
                if len(parts) >= 2 and re.match(r'^[a-fA-F0-9]{64}$', parts[0]):
                    h = parts[0].lower()
                    path = " ".join(parts[1:])
                    hashes[os.path.basename(path)] = h
                    hashes[path] = h
    except Exception:
        pass
    return hashes

# ---------------- Session correlation ----------------
def correlate_sessions(results: list, time_window_sec=SESSION_WINDOW_SEC,
                       min_events=SESSION_MIN_EVENTS, high_score_threshold=SESSION_HIGH_SCORE):
    """Group events (results) into time windows and produce session summaries.
    results: list of dicts with 'timestamp' (ISO str) and 'score' and 'label' etc.
    Returns a list of session dicts.
    """
    from datetime import datetime
    def to_dt(s):
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return datetime.now(timezone.utc)

    sorted_events = sorted(results, key=lambda x: to_dt(x["timestamp"]))
    sessions = []
    if not sorted_events:
        return sessions

    current = [sorted_events[0]]
    for ev in sorted_events[1:]:
        prev_dt = to_dt(current[-1]["timestamp"])
        now_dt = to_dt(ev["timestamp"])
        if (now_dt - prev_dt).total_seconds() <= time_window_sec:
            current.append(ev)
        else:
            sessions.append(current)
            current = [ev]
    if current:
        sessions.append(current)

    summarized = []
    for s in sessions:
        start = s[0]["timestamp"]
        end = s[-1]["timestamp"]
        scores = [ev.get("score", 0) for ev in s]
        avg_score = sum(scores) / len(scores) if scores else 0
        labels = {}
        for ev in s:
            labels[ev["label"]] = labels.get(ev["label"], 0) + 1
        priority = "HIGH_PRIORITY" if (len(s) >= min_events or avg_score >= high_score_threshold) else "NORMAL"
        summarized.append({
            "start": start,
            "end": end,
            "count": len(s),
            "avg_score": round(avg_score, 1),
            "labels": labels,
            "priority": priority,
            "events": s
        })
    return summarized

# ---------------- Worker that streams files and matches rules ----------------
class ParserWorker(threading.Thread):
    def __init__(self, files, rules, queue_callback, progress_callback, stop_event, manifest_map):
        super().__init__(daemon=True)
        self.files = files
        self.rules = [(lbl, re.compile(pat, re.IGNORECASE), score, desc) for (lbl, pat, score, desc) in rules]
        self.queue_callback = queue_callback
        self.progress_callback = progress_callback
        self.stop_event = stop_event
        self.manifest_map = manifest_map or {}

    def run(self):
        total_bytes = sum([f.stat().st_size for f in self.files])
        read_bytes = 0
        matches = 0
        try:
            for fpath in self.files:
                if self.stop_event.is_set():
                    break
                # open file and stream
                with fpath.open("r", encoding="utf-8", errors="ignore") as fh:
                    prev_lines = deque(maxlen=PRE_CONTEXT)
                    it = iter(fh)
                    for line in it:
                        if self.stop_event.is_set():
                            break
                        # check rules; first match wins (change if you want multi-match)
                        matched = False
                        for (label, cre, score, desc) in self.rules:
                            if cre.search(line):
                                # capture post-context
                                post_ctx = []
                                for _ in range(POST_CONTEXT):
                                    try:
                                        nxt = next(it)
                                        post_ctx.append(nxt.rstrip("\n"))
                                    except StopIteration:
                                        break
                                ts = try_extract_timestamp(line) or current_iso_utc()
                                match = {
                                    "timestamp": ts,
                                    "label": label,
                                    "score": score,
                                    "description": desc,
                                    "line": line.rstrip("\n"),
                                    "pre_context": list(prev_lines),
                                    "post_context": post_ctx,
                                    "source_file": str(fpath),
                                    "file_basename": os.path.basename(str(fpath)),
                                    # manifest lookup attempts
                                    "manifest_hash": self.lookup_hash_for_file(str(fpath))
                                }
                                matches += 1
                                self.queue_callback(match)
                                matched = True
                                break
                        prev_lines.append(line.rstrip("\n"))
                        # update read_bytes
                        try:
                            read_bytes += len(line.encode('utf-8'))
                        except Exception:
                            read_bytes += len(line)
                        if total_bytes > 0 and read_bytes % (5 * 1024 * 1024) < 2000:
                            pct = min(100.0, (read_bytes / float(total_bytes)) * 100.0)
                            self.progress_callback(pct)
                # small progress update per file
                self.progress_callback(min(100.0, (read_bytes / float(total_bytes)) * 100.0 if total_bytes else 100.0))
            # finished
            self.progress_callback(100.0)
            self.queue_callback({"_done": True, "matches": matches})
        except Exception as e:
            self.queue_callback({"_error": str(e)})

    def lookup_hash_for_file(self, path_str):
        # try direct path, basename, and relative components
        if not self.manifest_map:
            return ""
        # direct
        if path_str in self.manifest_map:
            return self.manifest_map[path_str]
        b = os.path.basename(path_str)
        if b in self.manifest_map:
            return self.manifest_map[b]
        # also check if any manifest key is substring of path (partial match)
        for k, v in self.manifest_map.items():
            if k and k in path_str:
                return v
        return ""

# ---------------- GUI ----------------
class ForensicParserGUI:
    def __init__(self, root):
        self.root = root
        root.title("Forensic Log Parser — iCloud Focused")
        root.geometry("1100x700")

        # Top controls
        top = ttk.Frame(root, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top, text="Log folder or files:").pack(side=tk.LEFT)
        self.path_entry = ttk.Entry(top, width=70)
        self.path_entry.pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse Folder", command=self.browse_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Browse Files", command=self.browse_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Stop", command=self.stop_scan).pack(side=tk.LEFT, padx=2)

        # Progress
        self.progress = ttk.Progressbar(root, length=980, mode="determinate")
        self.progress.pack(pady=6)

        # Mid area: tree of matches and session panel
        mid = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        mid.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Left: matches tree
        left = ttk.Frame(mid)
        mid.add(left, weight=3)
        cols = ("ts", "label", "score", "file", "excerpt")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w in zip(cols, (180, 120, 60, 260, 360)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w, anchor=tk.W)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.pack(side=tk.LEFT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scroll.set)

        # Right: details & sessions
        right = ttk.Frame(mid)
        mid.add(right, weight=2)

        ttk.Label(right, text="Selected match details (context):").pack(anchor=tk.W)
        self.details = ScrolledText(right, height=18)
        self.details.pack(fill=tk.BOTH, expand=True)

        # Sessions area
        sess_frame = ttk.Frame(right)
        sess_frame.pack(fill=tk.X, pady=6)
        ttk.Button(sess_frame, text="Export Matches CSV", command=self.export_matches_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(sess_frame, text="Export Sessions CSV", command=self.export_sessions_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(sess_frame, text="Show Sessions", command=self.show_sessions_window).pack(side=tk.LEFT, padx=4)
        ttk.Label(sess_frame, text="Session window (sec):").pack(side=tk.LEFT, padx=6)
        self.session_window_entry = ttk.Entry(sess_frame, width=6)
        self.session_window_entry.pack(side=tk.LEFT)
        self.session_window_entry.insert(0, str(SESSION_WINDOW_SEC))

        # internal state
        self.results = []   # list of match dicts
        self.sessions = []  # list of session dicts
        self.worker = None
        self.stop_event = threading.Event()
        self.manifest_map = {}

    # UI actions
    def browse_folder(self):
        p = filedialog.askdirectory(title="Select folder with log files")
        if p:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, p)

    def browse_files(self):
        fps = filedialog.askopenfilenames(title="Select log files", filetypes=[("Text files","*.txt *.log *.logarchive *.log*"), ("All","*.*")])
        if fps:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, ";".join(fps))

    # worker callbacks (called from worker via main thread scheduling)
    def queue_callback(self, item):
        self.root.after(1, self._process_queue_item, item)

    def progress_callback(self, pct):
        self.root.after(1, lambda: self.progress.configure(value=pct))

    def _process_queue_item(self, item):
        if "_error" in item:
            messagebox.showerror("Parser Error", item["_error"])
            self.stop_scan()
            return
        if "_done" in item:
            # run correlation now
            # read session window from UI
            try:
                wnd = int(self.session_window_entry.get().strip())
            except Exception:
                wnd = SESSION_WINDOW_SEC
            self.sessions = correlate_sessions(self.results, time_window_sec=wnd)
            high_count = sum(1 for s in self.sessions if s["priority"] == "HIGH_PRIORITY")
            messagebox.showinfo("Scan complete", f"Scan finished with {item.get('matches',0)} matches.\n{len(self.sessions)} sessions created, {high_count} HIGH_PRIORITY.")
            return
        # normal match
        idx = len(self.results)
        self.results.append(item)
        excerpt = item["line"]
        if len(excerpt) > 240:
            excerpt = excerpt[:240] + "..."
        self.tree.insert("", "end", iid=str(idx), values=(item["timestamp"], item["label"], item["score"], os.path.basename(item["source_file"]), excerpt))

    def start_scan(self):
        path_input = self.path_entry.get().strip()
        if not path_input:
            messagebox.showerror("Missing path", "Please enter a folder or files to scan.")
            return
        # determine list of files
        files = []
        if ";" in path_input:  # multiple files selected via browse_files
            for p in path_input.split(";"):
                if os.path.isfile(p):
                    files.append(Path(p))
        elif os.path.isdir(path_input):
            folder = Path(path_input)
            # pick large text-like files: .txt, .log, or any file >0 that looks like text
            for ext in ("*.log", "*.txt", "*.logarchive", "*.log*"):
                for fp in folder.rglob(ext):
                    if fp.is_file():
                        files.append(fp)
            # also include non-ext files (e.g., unified_log_21d) - include files > 0 and not binary by quick check
            for fp in folder.iterdir():
                if fp.is_file() and fp not in files:
                    files.append(fp)
        elif os.path.isfile(path_input):
            files.append(Path(path_input))
        else:
            messagebox.showerror("Invalid path", "The provided path is not valid.")
            return

        if not files:
            messagebox.showerror("No files found", "No log files found to scan.")
            return

        # reset UI list & state
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.results = []
        self.sessions = []
        self.progress.configure(value=0)
        self.stop_event.clear()

        # load manifest if present
        folder = Path(path_input) if os.path.isdir(path_input) else Path(path_input).parent
        manifest_path = folder / "collection_hashes.txt"
        if manifest_path.exists():
            self.manifest_map = load_hash_manifest(manifest_path)
            messagebox.showinfo("Manifest loaded", f"Loaded {len(self.manifest_map)} entries from manifest.")
        else:
            self.manifest_map = {}

        # create and start worker
        self.worker = ParserWorker(files, RULES, queue_callback=self.queue_callback,
                                   progress_callback=self.progress_callback, stop_event=self.stop_event,
                                   manifest_map=self.manifest_map)
        self.worker.start()
        messagebox.showinfo("Started", "Parser started in background. Matches will appear as found.")

    def stop_scan(self):
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            messagebox.showinfo("Stopping", "Stop requested; worker will halt shortly.")
        else:
            messagebox.showinfo("Not running", "No active scan to stop.")

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        item = self.results[idx]
        self.details.delete(1.0, tk.END)
        self.details.insert(tk.END, f"Timestamp: {item['timestamp']}\n")
        self.details.insert(tk.END, f"Label: {item['label']}  Score: {item['score']}\n")
        self.details.insert(tk.END, f"Description: {item['description']}\n")
        self.details.insert(tk.END, f"Source file: {item.get('source_file','')}\n")
        if item.get("manifest_hash"):
            self.details.insert(tk.END, f"Manifest SHA256: {item.get('manifest_hash')}\n")
        self.details.insert(tk.END, "\n--- Matched Line ---\n")
        self.details.insert(tk.END, item["line"] + "\n\n")
        self.details.insert(tk.END, "--- Pre-context ---\n")
        for pl in item["pre_context"]:
            self.details.insert(tk.END, pl + "\n")
        self.details.insert(tk.END, "\n--- Post-context ---\n")
        for pl in item["post_context"]:
            self.details.insert(tk.END, pl + "\n")
        self.details.see(1.0)

    # ---------------- Exports ----------------
    def export_matches_csv(self):
        if not self.results:
            messagebox.showwarning("No results", "No matches to export.")
            return
        out = filedialog.asksaveasfilename(title="Save matches CSV", defaultextension=".csv", initialfile=MATCHES_CSV)
        if not out:
            return
        try:
            with open(out, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.writer(csvf)
                writer.writerow(["timestamp","label","score","description","matched_line","pre_context","post_context","source_file","manifest_hash"])
                for r in self.results:
                    writer.writerow([
                        r.get("timestamp",""),
                        r.get("label",""),
                        r.get("score",""),
                        r.get("description",""),
                        r.get("line",""),
                        "\n".join(r.get("pre_context",[])),
                        "\n".join(r.get("post_context",[])),
                        r.get("source_file",""),
                        r.get("manifest_hash","")
                    ])
            messagebox.showinfo("Exported", f"Exported {len(self.results)} matches to {out}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def export_sessions_csv(self):
        if not self.sessions:
            messagebox.showwarning("No sessions", "No sessions available. Run a scan first.")
            return
        out = filedialog.asksaveasfilename(title="Save sessions CSV", defaultextension=".csv", initialfile=SESSIONS_CSV)
        if not out:
            return
        try:
            with open(out, "w", newline="", encoding="utf-8") as csvf:
                writer = csv.writer(csvf)
                writer.writerow(["start","end","count","avg_score","priority","labels_summary","event_timestamps_sample"])
                for s in self.sessions:
                    labels_summary = ";".join([f"{k}:{v}" for k,v in s["labels"].items()])
                    sample_ts = ";".join([ev["timestamp"] for ev in s["events"][:5]])
                    writer.writerow([s["start"], s["end"], s["count"], s["avg_score"], s["priority"], labels_summary, sample_ts])
            messagebox.showinfo("Exported", f"Exported {len(self.sessions)} sessions to {out}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def show_sessions_window(self):
        if not self.sessions:
            messagebox.showwarning("No sessions", "No sessions available. Run a scan first.")
            return
        win = tk.Toplevel(self.root)
        win.title("Sessions Overview")
        win.geometry("800x500")
        cols = ("start","end","count","avg_score","priority","labels")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c.upper())
            tree.column(c, width=120)
        tree.pack(fill=tk.BOTH, expand=True)
        for i, s in enumerate(self.sessions):
            labels_summary = ", ".join([f"{k}:{v}" for k,v in s["labels"].items()])
            tree.insert("", "end", iid=str(i), values=(s["start"], s["end"], s["count"], s["avg_score"], s["priority"], labels_summary))
        def on_sess_select(evt):
            sel = tree.selection()
            if not sel:
                return
            idx = int(sel[0])
            s = self.sessions[idx]
            # show session events in a detail window
            dwin = tk.Toplevel(win)
            dwin.title(f"Session {idx} events")
            txt = ScrolledText(dwin, height=30)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, f"Session {idx}\nPriority: {s['priority']}\nStart: {s['start']}\nEnd: {s['end']}\nCount: {s['count']}\nAvg score: {s['avg_score']}\n\n")
            for ev in s["events"]:
                txt.insert(tk.END, f"{ev['timestamp']} | {ev['label']} | {ev['score']} | {os.path.basename(ev.get('source_file',''))}\n")
                txt.insert(tk.END, "  -> " + ev.get("line","")[:400] + "\n\n")
        tree.bind("<<TreeviewSelect>>", on_sess_select)

# ---------------- Main ----------------
def main():
    root = tk.Tk()
    app = ForensicParserGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
