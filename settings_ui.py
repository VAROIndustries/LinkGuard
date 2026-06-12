"""
Settings window — General, APIs, Whitelist, Blacklist, History tabs.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import webbrowser
from datetime import datetime

import database as db
import startup

COLORS = {
    "bg":      "#1a1a2e",
    "panel":   "#16213e",
    "border":  "#0f3460",
    "accent":  "#e94560",
    "clean":   "#27ae60",
    "warn":    "#f39c12",
    "danger":  "#e74c3c",
    "text":    "#eaeaea",
    "muted":   "#8899aa",
    "input_bg":"#0d1b2a",
    "white":   "#ffffff",
}


class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, on_settings_changed=None):
        super().__init__(parent)
        self.on_settings_changed = on_settings_changed
        self.title("LinkGuard — Settings")
        self.configure(bg=COLORS["bg"])
        self.geometry("680x520")
        self.resizable(True, True)
        self.minsize(600, 480)

        self._settings = db.get_all_settings()
        self._vars: dict[str, tk.Variable] = {}

        self._build()
        self._center()
        self.lift()
        self.attributes("-topmost", True)
        self.focus_force()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        # Title bar
        hdr = tk.Frame(self, bg=COLORS["accent"], height=4)
        hdr.pack(fill="x")

        title_row = tk.Frame(self, bg=COLORS["panel"], pady=12, padx=20)
        title_row.pack(fill="x")
        tk.Label(title_row, text="⚙  Settings", font=("Segoe UI", 13, "bold"),
                 bg=COLORS["panel"], fg=COLORS["text"]).pack(side="left")

        # Notebook
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["panel"],
                        foreground=COLORS["muted"], padding=[14, 6],
                        font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["border"])],
                  foreground=[("selected", COLORS["white"])])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=(8, 0))

        nb.add(self._tab_general(nb),  text="General")
        nb.add(self._tab_apis(nb),     text="APIs")
        nb.add(self._tab_whitelist(nb), text="Whitelist")
        nb.add(self._tab_blacklist(nb), text="Blacklist")
        nb.add(self._tab_history(nb),  text="History")

        # Footer
        footer = tk.Frame(self, bg=COLORS["bg"], pady=10, padx=12)
        footer.pack(fill="x")
        _btn(footer, "Save & Close", COLORS["accent"], COLORS["white"],
             self._save_and_close).pack(side="right")
        _btn(footer, "Cancel", COLORS["panel"], COLORS["muted"],
             self.destroy).pack(side="right", padx=8)

    # ── General tab ───────────────────────────────────────────────────────────

    def _tab_general(self, parent) -> tk.Frame:
        f = _tab_frame(parent)

        _section(f, "Behavior")
        self._vars["startup"] = _checkbox(
            f, "Start with Windows",
            self._settings.get("startup", "true") == "true"
        )
        self._vars["clipboard_monitoring"] = _checkbox(
            f, "Monitor clipboard for URLs",
            self._settings.get("clipboard_monitoring", "true") == "true"
        )
        self._vars["notify_clean"] = _checkbox(
            f, "Show notification for clean URLs too",
            self._settings.get("notify_clean", "false") == "true"
        )

        _section(f, "Protocol Handler  (intercepts all clicked links)")
        ph_enabled = startup.is_protocol_handler_enabled()
        self._vars["protocol_handler"] = _checkbox(
            f, "Intercept all http/https link clicks",
            ph_enabled,
            note="When enabled, LinkGuard checks every link before it opens in your browser."
        )

        _section(f, "Risk Threshold  (minimum level to show alert)")
        threshold_frame = tk.Frame(f, bg=COLORS["bg"])
        threshold_frame.pack(fill="x", padx=20, pady=4)
        self._vars["risk_threshold"] = tk.StringVar(
            value=self._settings.get("risk_threshold", "suspicious")
        )
        for val, label in [("suspicious", "Suspicious & above"), ("phishing", "Phishing only")]:
            tk.Radiobutton(
                threshold_frame, text=label, variable=self._vars["risk_threshold"],
                value=val, bg=COLORS["bg"], fg=COLORS["text"],
                selectcolor=COLORS["border"], activebackground=COLORS["bg"],
                font=("Segoe UI", 9)
            ).pack(side="left", padx=(0, 20))

        return f

    # ── APIs tab ──────────────────────────────────────────────────────────────

    def _tab_apis(self, parent) -> tk.Frame:
        f = _tab_frame(parent)

        _section(f, "Google Safe Browsing  (free, 10,000 req/day)")
        tk.Label(f, text="Get a key at console.cloud.google.com → Safe Browsing API",
                 font=("Segoe UI", 8), bg=COLORS["bg"], fg=COLORS["muted"]).pack(
            anchor="w", padx=20, pady=(0, 4))
        self._vars["google_sbrowsing_key"] = _entry(
            f, self._settings.get("google_sbrowsing_key", ""),
            placeholder="AIza..."
        )

        _section(f, "VirusTotal  (free, 4 req/min)")
        tk.Label(f, text="Get a key at virustotal.com → Your API key",
                 font=("Segoe UI", 8), bg=COLORS["bg"], fg=COLORS["muted"]).pack(
            anchor="w", padx=20, pady=(0, 4))
        self._vars["virustotal_key"] = _entry(
            f, self._settings.get("virustotal_key", ""),
            placeholder="64-character hex key"
        )

        tk.Label(f,
                 text="API keys are stored locally and never sent anywhere except the respective API.",
                 font=("Segoe UI", 8, "italic"),
                 bg=COLORS["bg"], fg=COLORS["muted"], wraplength=580).pack(
            anchor="w", padx=20, pady=(20, 0))
        return f

    # ── Whitelist tab ─────────────────────────────────────────────────────────

    def _tab_whitelist(self, parent) -> tk.Frame:
        f = _tab_frame(parent)
        tk.Label(f, text="Domains that are always allowed without a prompt.",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["muted"]).pack(
            anchor="w", padx=20, pady=(8, 4))
        self._wl_list = _domain_list(f, db.get_whitelist,
                                     db.remove_whitelist, db.add_whitelist)
        return f

    # ── Blacklist tab ─────────────────────────────────────────────────────────

    def _tab_blacklist(self, parent) -> tk.Frame:
        f = _tab_frame(parent)
        tk.Label(f, text="Domains that are always blocked.",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["muted"]).pack(
            anchor="w", padx=20, pady=(8, 4))
        self._bl_list = _domain_list(f, db.get_blacklist,
                                     db.remove_blacklist,
                                     lambda d: db.add_blacklist(d, "Manually added"))
        return f

    # ── History tab ───────────────────────────────────────────────────────────

    def _tab_history(self, parent) -> tk.Frame:
        f = _tab_frame(parent)

        toolbar = tk.Frame(f, bg=COLORS["bg"])
        toolbar.pack(fill="x", padx=20, pady=(8, 4))
        tk.Label(toolbar, text="Recently checked URLs (newest first)",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["muted"]).pack(side="left")
        _btn(toolbar, "Clear history", COLORS["border"], COLORS["muted"],
             self._clear_history).pack(side="right")

        cols = ("checked_at", "domain", "risk_level", "action")
        tv = _treeview(f, cols, [("checked_at", "Time", 130), ("domain", "Domain", 180),
                                 ("risk_level", "Risk", 90), ("action", "Action", 90)])
        self._history_tv = tv

        self._reload_history()
        return f

    def _reload_history(self):
        tv = self._history_tv
        tv.delete(*tv.get_children())
        for row in db.get_history(200):
            tv.insert("", "end", values=(
                row["checked_at"][:16],
                row["domain"],
                row["risk_level"],
                row["action"] or "—",
            ))

    def _clear_history(self):
        if messagebox.askyesno("Clear history", "Delete all URL check history?",
                               parent=self):
            db.clear_history()
            self._reload_history()

    # ── Save ──────────────────────────────────────────────────────────────────

    def _save_and_close(self):
        for key, var in self._vars.items():
            if isinstance(var, tk.BooleanVar):
                db.set_setting(key, "true" if var.get() else "false")
            elif isinstance(var, (tk.StringVar, tk.Entry)):
                val = var.get() if isinstance(var, tk.StringVar) else var.get()
                db.set_setting(key, val.strip())

        # Apply startup setting
        want_startup = self._vars["startup"].get()
        if want_startup and not startup.is_startup_enabled():
            startup.enable_startup()
        elif not want_startup and startup.is_startup_enabled():
            startup.disable_startup()

        # Apply protocol handler setting
        want_ph = self._vars["protocol_handler"].get()
        ph_active = startup.is_protocol_handler_enabled()
        if want_ph and not ph_active:
            ok = startup.enable_protocol_handler()
            if not ok:
                messagebox.showerror("Protocol Handler",
                    "Could not register as URL handler.\n"
                    "Try running LinkGuard as administrator.", parent=self)
        elif not want_ph and ph_active:
            startup.disable_protocol_handler()

        if self.on_settings_changed:
            self.on_settings_changed()

        self.destroy()

    def _center(self):
        self.update_idletasks()
        w, h = 680, 520
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


# ── Widget helpers ────────────────────────────────────────────────────────────

def _tab_frame(parent) -> tk.Frame:
    f = tk.Frame(parent, bg=COLORS["bg"])
    f.pack(fill="both", expand=True)
    return f


def _section(parent, title: str):
    tk.Frame(parent, bg=COLORS["border"], height=1).pack(fill="x", padx=20, pady=(14, 6))
    tk.Label(parent, text=title.upper(), font=("Segoe UI", 8, "bold"),
             bg=COLORS["bg"], fg=COLORS["muted"]).pack(anchor="w", padx=20)


def _checkbox(parent, label: str, value: bool, note: str = "") -> tk.BooleanVar:
    var = tk.BooleanVar(value=value)
    row = tk.Frame(parent, bg=COLORS["bg"])
    row.pack(anchor="w", padx=20, pady=3)
    cb = tk.Checkbutton(row, text=label, variable=var, bg=COLORS["bg"],
                        fg=COLORS["text"], selectcolor=COLORS["border"],
                        activebackground=COLORS["bg"], font=("Segoe UI", 9))
    cb.pack(side="left")
    if note:
        tk.Label(row, text=f"  ({note})", font=("Segoe UI", 8), bg=COLORS["bg"],
                 fg=COLORS["muted"], wraplength=400).pack(side="left")
    return var


def _entry(parent, value: str, placeholder: str = "") -> tk.Entry:
    row = tk.Frame(parent, bg=COLORS["bg"])
    row.pack(fill="x", padx=20, pady=4)
    e = tk.Entry(row, bg=COLORS["input_bg"], fg=COLORS["text"],
                 insertbackground=COLORS["text"], relief="flat",
                 font=("Consolas", 9), bd=0)
    e.pack(fill="x", ipady=6, padx=2)
    if value:
        e.insert(0, value)
    elif placeholder:
        e.insert(0, placeholder)
        e.config(fg=COLORS["muted"])
        def on_focus_in(ev):
            if e.get() == placeholder:
                e.delete(0, "end")
                e.config(fg=COLORS["text"])
        def on_focus_out(ev):
            if not e.get():
                e.insert(0, placeholder)
                e.config(fg=COLORS["muted"])
        e.bind("<FocusIn>", on_focus_in)
        e.bind("<FocusOut>", on_focus_out)
    return e


def _btn(parent, text: str, bg: str, fg: str, cmd) -> tk.Button:
    return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                     font=("Segoe UI", 9), relief="flat", bd=0,
                     padx=12, pady=6, cursor="hand2",
                     activebackground=COLORS["border"],
                     activeforeground=COLORS["white"])


def _domain_list(parent, load_fn, remove_fn, add_fn) -> ttk.Treeview:
    """A two-column (domain, added) treeview with Add/Remove buttons."""
    toolbar = tk.Frame(parent, bg=COLORS["bg"])
    toolbar.pack(fill="x", padx=20, pady=(0, 4))

    tv = _treeview(parent,
                   ("domain", "added_at"),
                   [("domain", "Domain", 280), ("added_at", "Added", 130)])

    def reload():
        tv.delete(*tv.get_children())
        for row in load_fn():
            tv.insert("", "end", values=(row["domain"], row.get("added_at", "")[:16]))

    def add():
        d = simpledialog.askstring("Add domain", "Enter domain (e.g. google.com):",
                                   parent=parent)
        if d and d.strip():
            add_fn(d.strip().lower())
            reload()

    def remove():
        sel = tv.selection()
        if not sel:
            return
        domain = tv.item(sel[0])["values"][0]
        remove_fn(domain)
        reload()

    _btn(toolbar, "+ Add", COLORS["clean"], COLORS["white"], add).pack(side="left")
    _btn(toolbar, "Remove", COLORS["danger"], COLORS["white"], remove).pack(side="left", padx=8)

    reload()
    return tv


def _treeview(parent, cols, col_defs) -> ttk.Treeview:
    style = ttk.Style()
    style.configure("Dark.Treeview",
                    background=COLORS["panel"],
                    foreground=COLORS["text"],
                    fieldbackground=COLORS["panel"],
                    borderwidth=0,
                    rowheight=24)
    style.configure("Dark.Treeview.Heading",
                    background=COLORS["border"],
                    foreground=COLORS["muted"],
                    relief="flat")
    style.map("Dark.Treeview", background=[("selected", COLORS["border"])])

    frame = tk.Frame(parent, bg=COLORS["bg"])
    frame.pack(fill="both", expand=True, padx=20, pady=4)

    tv = ttk.Treeview(frame, columns=cols, show="headings",
                      style="Dark.Treeview", height=10)
    for col, heading, width in col_defs:
        tv.heading(col, text=heading)
        tv.column(col, width=width, minwidth=60)

    sb = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=sb.set)
    tv.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return tv
