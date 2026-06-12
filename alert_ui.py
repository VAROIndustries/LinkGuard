"""
Alert dialog shown when a suspicious or phishing URL is detected.
Returns the user's decision: "allow_once", "whitelist", "blacklist", "cancel"
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, font as tkfont
import threading
import queue
from typing import Optional
from checker import RiskResult

# Keep a reference to prevent garbage collection
_active_alerts: list = []
_lock = threading.Lock()

COLORS = {
    "bg":         "#1a1a2e",
    "panel":      "#16213e",
    "border":     "#0f3460",
    "clean":      "#27ae60",
    "suspicious": "#f39c12",
    "phishing":   "#e74c3c",
    "text":       "#eaeaea",
    "muted":      "#8899aa",
    "btn_bg":     "#0f3460",
    "btn_hover":  "#1a4a80",
    "white":      "#ffffff",
}


def show_alert(result: RiskResult) -> str:
    """
    Show the alert dialog (blocks until user responds).
    Returns: "allow_once" | "whitelist" | "blacklist" | "cancel"
    Must be called from the main tkinter thread.
    """
    dlg = AlertDialog(result)
    dlg.mainloop()
    return dlg.decision


class AlertDialog(tk.Tk):
    def __init__(self, result: RiskResult):
        super().__init__()
        self.result = result
        self.decision = "cancel"

        self._build_ui()
        self._center()
        self.protocol("WM_DELETE_WINDOW", lambda: self._decide("cancel"))
        self.lift()
        self.attributes("-topmost", True)
        self.focus_force()

    def _build_ui(self):
        r = self.result
        level_color = COLORS.get(r.level, COLORS["muted"])

        self.title("PhishUrl — URL Check")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self.geometry("540x420")

        # ── Header banner ──────────────────────────────────────────────────
        banner = tk.Frame(self, bg=level_color, height=6)
        banner.pack(fill="x")

        header = tk.Frame(self, bg=COLORS["panel"], pady=18)
        header.pack(fill="x", padx=0)

        emoji_label = tk.Label(
            header, text=r.emoji, font=("Segoe UI Emoji", 28),
            bg=COLORS["panel"], fg=level_color
        )
        emoji_label.pack()

        level_text = r.level.upper()
        tk.Label(
            header, text=level_text,
            font=("Segoe UI", 16, "bold"),
            bg=COLORS["panel"], fg=level_color
        ).pack()

        if r.level == "phishing":
            sub = "This URL matches known phishing patterns. Do NOT proceed."
        elif r.level == "suspicious":
            sub = "This URL has suspicious characteristics. Proceed with caution."
        else:
            sub = "This URL appears safe."

        tk.Label(
            header, text=sub,
            font=("Segoe UI", 9),
            bg=COLORS["panel"], fg=COLORS["muted"],
            wraplength=480
        ).pack(pady=(4, 0))

        # ── URL display ────────────────────────────────────────────────────
        url_frame = tk.Frame(self, bg=COLORS["bg"], pady=12, padx=20)
        url_frame.pack(fill="x")

        tk.Label(
            url_frame, text="URL",
            font=("Segoe UI", 8, "bold"),
            bg=COLORS["bg"], fg=COLORS["muted"]
        ).pack(anchor="w")

        url_box = tk.Frame(url_frame, bg=COLORS["border"], pady=1, padx=1)
        url_box.pack(fill="x", pady=(2, 0))
        url_inner = tk.Frame(url_box, bg=COLORS["panel"])
        url_inner.pack(fill="x")

        display_url = r.url if len(r.url) <= 80 else r.url[:77] + "…"
        tk.Label(
            url_inner, text=display_url,
            font=("Consolas", 9),
            bg=COLORS["panel"], fg=COLORS["text"],
            wraplength=480, justify="left", padx=8, pady=8
        ).pack(anchor="w")

        tk.Label(
            url_frame, text=f"Domain: {r.domain}",
            font=("Segoe UI", 8),
            bg=COLORS["bg"], fg=COLORS["muted"]
        ).pack(anchor="w", pady=(4, 0))

        # ── Risk score bar ─────────────────────────────────────────────────
        score_frame = tk.Frame(self, bg=COLORS["bg"], padx=20)
        score_frame.pack(fill="x")

        tk.Label(
            score_frame, text=f"Risk score: {r.score}/100",
            font=("Segoe UI", 8, "bold"),
            bg=COLORS["bg"], fg=COLORS["muted"]
        ).pack(anchor="w")

        bar_bg = tk.Frame(score_frame, bg="#2a2a3e", height=8)
        bar_bg.pack(fill="x", pady=(3, 8))
        bar_bg.update_idletasks()
        bar_width = max(1, int((bar_bg.winfo_reqwidth() or 500) * r.score / 100))
        tk.Frame(bar_bg, bg=level_color, height=8, width=bar_width).place(x=0, y=0, relwidth=r.score/100, relheight=1)

        # ── Reasons ────────────────────────────────────────────────────────
        if r.reasons:
            reasons_frame = tk.Frame(self, bg=COLORS["bg"], padx=20)
            reasons_frame.pack(fill="x")
            tk.Label(
                reasons_frame, text="FINDINGS",
                font=("Segoe UI", 8, "bold"),
                bg=COLORS["bg"], fg=COLORS["muted"]
            ).pack(anchor="w")
            for reason in r.reasons[:5]:
                row = tk.Frame(reasons_frame, bg=COLORS["bg"])
                row.pack(fill="x", pady=1)
                tk.Label(row, text="•", font=("Segoe UI", 9), bg=COLORS["bg"],
                         fg=level_color).pack(side="left", padx=(0, 6))
                tk.Label(row, text=reason, font=("Segoe UI", 9),
                         bg=COLORS["bg"], fg=COLORS["text"],
                         wraplength=440, justify="left").pack(side="left", anchor="w")

        # ── Buttons ────────────────────────────────────────────────────────
        self.pack_propagate(True)
        btn_frame = tk.Frame(self, bg=COLORS["bg"], pady=16, padx=20)
        btn_frame.pack(fill="x", side="bottom")

        if r.level == "phishing":
            # Phishing: Block is primary, allow is secondary/dangerous
            _make_btn(btn_frame, "Block domain", level_color, COLORS["white"],
                      lambda: self._decide("blacklist")).pack(side="left")
            _make_btn(btn_frame, "Allow once", COLORS["btn_bg"], COLORS["muted"],
                      lambda: self._decide("allow_once")).pack(side="left", padx=8)
        elif r.level == "suspicious":
            _make_btn(btn_frame, "Open anyway", COLORS["btn_bg"], COLORS["text"],
                      lambda: self._decide("allow_once")).pack(side="left")
            _make_btn(btn_frame, "Always allow", COLORS["clean"], COLORS["white"],
                      lambda: self._decide("whitelist")).pack(side="left", padx=8)
            _make_btn(btn_frame, "Block domain", level_color, COLORS["white"],
                      lambda: self._decide("blacklist")).pack(side="left")
        else:
            _make_btn(btn_frame, "Open", COLORS["clean"], COLORS["white"],
                      lambda: self._decide("allow_once")).pack(side="left")
            _make_btn(btn_frame, "Always allow", COLORS["btn_bg"], COLORS["text"],
                      lambda: self._decide("whitelist")).pack(side="left", padx=8)

        _make_btn(btn_frame, "✕ Dismiss", COLORS["bg"], COLORS["muted"],
                  lambda: self._decide("cancel")).pack(side="right")

    def _decide(self, decision: str):
        self.decision = decision
        self.quit()
        self.destroy()

    def _center(self):
        self.update_idletasks()
        w, h = 540, 420
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2 - 40
        self.geometry(f"{w}x{h}+{x}+{y}")


def _make_btn(parent, text: str, bg: str, fg: str, cmd) -> tk.Button:
    btn = tk.Button(
        parent, text=text, command=cmd,
        bg=bg, fg=fg,
        font=("Segoe UI", 9, "bold"),
        relief="flat", bd=0,
        padx=14, pady=7,
        cursor="hand2",
        activebackground=COLORS["btn_hover"],
        activeforeground=COLORS["white"],
    )
    return btn
