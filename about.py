"""About window: version info and links to varo.industries. Not unit-tested (UI)."""
from __future__ import annotations

import tkinter as tk
import webbrowser

__version__ = "1.0.0"

TAGLINE = "Phishing URL checker for your system tray."
TOOL_URL = "https://varo.industries/apps#github"
GITHUB_URL = "https://github.com/VAROIndustries/LinkGuard"

COLORS = {
    "bg":     "#1a1a2e",
    "panel":  "#16213e",
    "accent": "#e94560",
    "link":   "#4ea1e9",
    "text":   "#eaeaea",
    "muted":  "#8899aa",
}


class AboutWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About LinkGuard")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)

        self._build()
        self._center()
        self.lift()
        self.attributes("-topmost", True)
        self.focus_force()

    def _build(self):
        # Accent strip
        tk.Frame(self, bg=COLORS["accent"], height=4).pack(fill="x")

        pad = tk.Frame(self, bg=COLORS["bg"], padx=32, pady=22)
        pad.pack()

        tk.Label(pad, text="🛡  LinkGuard", font=("Segoe UI", 17, "bold"),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack()
        tk.Label(pad, text=f"Version {__version__}", font=("Segoe UI", 9),
                 bg=COLORS["bg"], fg=COLORS["muted"]).pack(pady=(3, 0))
        tk.Label(pad, text=TAGLINE, font=("Segoe UI", 10),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(pady=(8, 14))

        self._link(pad, "varo.industries/apps", TOOL_URL)
        self._link(pad, "github.com/VAROIndustries/LinkGuard", GITHUB_URL)

        tk.Label(pad, text="© 2026 VARØ Industries", font=("Segoe UI", 8),
                 bg=COLORS["bg"], fg=COLORS["muted"]).pack(pady=(14, 12))

        tk.Button(pad, text="Close", width=10, command=self.destroy,
                  bg=COLORS["panel"], fg=COLORS["text"],
                  activebackground=COLORS["accent"], activeforeground=COLORS["text"],
                  relief="flat", cursor="hand2").pack()

    def _link(self, parent, text, url):
        lbl = tk.Label(parent, text=text, fg=COLORS["link"], bg=COLORS["bg"],
                       cursor="hand2", font=("Segoe UI", 9, "underline"))
        lbl.pack(pady=1)
        lbl.bind("<Button-1>", lambda e: webbrowser.open(url))
        return lbl

    def _center(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")
