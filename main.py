"""
LinkGuard — System tray phishing URL checker.

Entry point behavior:
  - No args:         start tray app normally
  - sys.argv[1] URL: protocol handler mode (check that URL, open in real browser)
  - --check <url>:   same as above (explicit)
"""
from __future__ import annotations

import sys
import os
import logging
import threading
import queue
import time
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
from database import APP_DIR
LOG_FILE = APP_DIR / "linkguard.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("linkguard")


def main():
    import database as db
    db.init_db()

    # ── Protocol handler mode ─────────────────────────────────────────────────
    url_arg = None
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--check" and len(sys.argv) > 2:
            url_arg = sys.argv[2]
        elif arg.startswith(("http://", "https://", "ftp://")):
            url_arg = arg

    if url_arg:
        _handle_url_arg(url_arg)
        return

    # ── Single-instance check ─────────────────────────────────────────────────
    lock_file = APP_DIR / "linkguard.lock"
    if _is_already_running(lock_file):
        log.warning("LinkGuard is already running.")
        _show_already_running_msg()
        return

    # ── Normal tray mode ──────────────────────────────────────────────────────
    app = LinkGuardApp(lock_file)
    app.run()


def _handle_url_arg(url: str):
    """Protocol handler: check the URL, show alert if needed, then open in browser."""
    import database as db
    from urllib.parse import urlparse
    from checker import check_url
    import startup as su

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # Blacklisted → block silently (no browser open)
    if db.is_blacklisted(domain):
        log.info("Blocked blacklisted domain: %s", domain)
        _show_blocked_toast(url, domain)
        db.add_history(url, domain, 100, "phishing", ["Manually blacklisted"], "blocked")
        return

    # Whitelisted → open directly
    if db.is_whitelisted(domain):
        log.info("Whitelisted, opening: %s", domain)
        su.open_in_real_browser(url)
        db.add_history(url, domain, 0, "clean", ["Whitelisted"], "opened")
        return

    # Run check
    gsb_key = db.get_setting("google_sbrowsing_key")
    vt_key  = db.get_setting("virustotal_key")
    result  = check_url(url, gsb_key=gsb_key, vt_key=vt_key)
    threshold = db.get_setting("risk_threshold")

    should_alert = (
        (threshold == "suspicious" and result.level in ("suspicious", "phishing")) or
        (threshold == "phishing"   and result.level == "phishing")
    )

    if not should_alert:
        su.open_in_real_browser(url)
        db.add_history(url, domain, result.score, result.level, result.reasons, "opened")
        return

    # Show alert dialog
    import tkinter as tk
    from alert_ui import show_alert

    root = tk.Tk()
    root.withdraw()
    decision = show_alert(result)
    root.destroy()

    if decision == "whitelist":
        db.add_whitelist(domain)
        su.open_in_real_browser(url)
        db.add_history(url, domain, result.score, result.level, result.reasons, "whitelisted+opened")
    elif decision == "blacklist":
        db.add_blacklist(domain, "Blocked from alert")
        db.add_history(url, domain, result.score, result.level, result.reasons, "blacklisted")
    elif decision == "allow_once":
        su.open_in_real_browser(url)
        db.add_history(url, domain, result.score, result.level, result.reasons, "allowed_once")
    else:
        db.add_history(url, domain, result.score, result.level, result.reasons, "dismissed")


def _show_blocked_toast(url: str, domain: str):
    """Minimal toast-style notification for blocked domain."""
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    from tkinter import messagebox
    messagebox.showwarning(
        "LinkGuard — Blocked",
        f"The domain '{domain}' is on your blacklist.\nURL was not opened.",
        parent=root
    )
    root.destroy()


def _is_already_running(lock_file: Path) -> bool:
    """Check if another instance is running via a PID lock file."""
    if lock_file.exists():
        try:
            pid = int(lock_file.read_text().strip())
            # Check if process with that PID exists
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
        except Exception:
            pass
        lock_file.unlink(missing_ok=True)
    lock_file.write_text(str(os.getpid()))
    return False


def _show_already_running_msg():
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("LinkGuard", "LinkGuard is already running in the system tray.")
    root.destroy()


# ── Main App ──────────────────────────────────────────────────────────────────

class LinkGuardApp:
    """
    Manages the system tray icon, clipboard monitor, and URL check queue.
    Tray runs in a background thread; tkinter UI stays on the main thread.
    """

    def __init__(self, lock_file: Path):
        import database as db
        import startup as su
        from icon_gen import make_all_icons

        self._lock_file = lock_file
        self._check_queue: queue.Queue = queue.Queue()   # URLs to check
        self._action_queue: queue.Queue = queue.Queue()  # tray actions → main thread
        self._icons = make_all_icons(size=64)
        self._tray = None
        self._clipboard_mon = None
        self._paused = False

        # Apply startup setting on first run
        if db.get_setting("startup") == "true" and not su.is_startup_enabled():
            su.enable_startup()

    def run(self):
        """Start everything and enter the tkinter main loop."""
        import tkinter as tk

        self._root = tk.Tk()
        self._root.withdraw()
        self._root.protocol("WM_DELETE_WINDOW", self._root.withdraw)

        self._start_tray()
        self._apply_clipboard_monitor()

        # Drive both queues from the tkinter main loop (thread-safe polling)
        self._root.after(200, self._process_queues)

        log.info("LinkGuard started (PID %s)", os.getpid())
        self._root.mainloop()
        self._shutdown()

    # ── Tray ──────────────────────────────────────────────────────────────────

    def _start_tray(self):
        import pystray
        from pystray import MenuItem, Menu
        from PIL import Image

        icons = self._icons

        # All callbacks post to _action_queue — never touch tkinter from here.
        # The main thread drains the queue via _process_queues().
        def pause_resume(icon, item):
            self._action_queue.put("pause_resume")

        def check_url_menu(icon, item):
            self._action_queue.put("check_url")

        def open_settings(icon, item):
            self._action_queue.put("settings")

        def quit_app(icon, item):
            self._action_queue.put("quit")

        menu = Menu(
            MenuItem("LinkGuard — Active", None, enabled=False),
            Menu.SEPARATOR,
            MenuItem("Check a URL…",       check_url_menu),
            MenuItem("Settings…",          open_settings),
            Menu.SEPARATOR,
            MenuItem("Pause monitoring",   pause_resume),
            Menu.SEPARATOR,
            MenuItem("Quit",               quit_app),
        )

        self._tray = pystray.Icon(
            "LinkGuard",
            icons["normal"],
            "LinkGuard — Active",
            menu=menu,
        )
        self._tray.run_detached()

    # ── Clipboard monitor ─────────────────────────────────────────────────────

    def _apply_clipboard_monitor(self):
        import database as db
        from clipboard_monitor import ClipboardMonitor

        if db.get_setting("clipboard_monitoring") == "true":
            if not self._clipboard_mon:
                self._clipboard_mon = ClipboardMonitor(
                    on_url=self._enqueue_url
                )
                self._clipboard_mon.start()
                log.info("Clipboard monitor started")
        else:
            if self._clipboard_mon:
                self._clipboard_mon.stop()
                self._clipboard_mon = None

    def _enqueue_url(self, url: str):
        """Called from clipboard monitor thread — safe to enqueue."""
        if not self._paused:
            self._check_queue.put(url)

    # ── Queue processing (main thread only) ──────────────────────────────────

    def _process_queues(self):
        """Drain both queues. Runs on the main thread via root.after() polling."""
        # Tray actions
        try:
            while True:
                action = self._action_queue.get_nowait()
                self._handle_tray_action(action)
        except queue.Empty:
            pass

        # URL checks
        try:
            while True:
                url = self._check_queue.get_nowait()
                self._process_url(url)
        except queue.Empty:
            pass

        self._root.after(200, self._process_queues)

    def _handle_tray_action(self, action: str):
        if action == "quit":
            self._quit()
        elif action == "check_url":
            self._show_manual_check_dialog()
        elif action == "settings":
            self._show_settings()
        elif action == "pause_resume":
            self._paused = not self._paused
            icon_key = "inactive" if self._paused else "normal"
            title = "LinkGuard (paused)" if self._paused else "LinkGuard — Active"
            if self._tray:
                self._tray.icon = self._icons[icon_key]
                self._tray.title = title
            log.info("Monitoring %s", "paused" if self._paused else "resumed")

    def _process_url(self, url: str):
        import database as db
        from urllib.parse import urlparse
        from checker import check_url
        from alert_ui import show_alert

        parsed = urlparse(url if "://" in url else "https://" + url)
        domain = parsed.hostname or ""

        if db.is_whitelisted(domain):
            log.debug("Whitelisted: %s", domain)
            return

        if db.is_blacklisted(domain):
            log.info("Blacklisted: %s", domain)
            self._flash_icon("alert")
            db.add_history(url, domain, 100, "phishing", ["Blacklisted"], "blocked")
            self._show_blacklist_toast(url, domain)
            return

        gsb_key = db.get_setting("google_sbrowsing_key")
        vt_key  = db.get_setting("virustotal_key")

        # Run check in background thread to avoid blocking UI
        def do_check():
            result = check_url(url, gsb_key=gsb_key, vt_key=vt_key)
            self._root.after(0, lambda: self._on_result(result))

        threading.Thread(target=do_check, daemon=True).start()

    def _on_result(self, result):
        import database as db
        from alert_ui import show_alert

        threshold = db.get_setting("risk_threshold")
        notify_clean = db.get_setting("notify_clean") == "true"

        should_alert = (
            notify_clean or
            (threshold == "suspicious" and result.level in ("suspicious", "phishing")) or
            (threshold == "phishing"   and result.level == "phishing")
        )

        if not should_alert:
            db.add_history(result.url, result.domain, result.score,
                           result.level, result.reasons, "auto_allowed")
            return

        # Flash icon to grab attention
        self._flash_icon(result.level if result.level != "clean" else "normal")

        decision = show_alert(result)

        action = decision
        if decision == "whitelist":
            db.add_whitelist(result.domain)
        elif decision == "blacklist":
            db.add_blacklist(result.domain, "Blocked from alert")

        db.add_history(result.url, result.domain, result.score,
                       result.level, result.reasons, action)
        log.info("URL %s | score=%d level=%s action=%s",
                 result.domain, result.score, result.level, action)

        # Restore normal icon
        self._root.after(3000, self._restore_icon)

    def _flash_icon(self, state: str):
        state_map = {"alert": "alert", "phishing": "alert", "suspicious": "warning",
                     "clean": "normal", "normal": "normal"}
        icon_key = state_map.get(state, "normal")
        if self._tray:
            self._tray.icon = self._icons[icon_key]

    def _restore_icon(self):
        if self._tray and not self._paused:
            self._tray.icon = self._icons["normal"]

    def _show_blacklist_toast(self, url: str, domain: str):
        from tkinter import messagebox
        messagebox.showwarning(
            "LinkGuard — Blocked",
            f"Blocked blacklisted domain:\n{domain}",
            parent=self._root
        )

    # ── Dialogs ───────────────────────────────────────────────────────────────

    def _show_manual_check_dialog(self):
        from tkinter import simpledialog
        url = simpledialog.askstring(
            "Check URL", "Enter a URL to check:",
            parent=self._root
        )
        if url and url.strip():
            self._process_url(url.strip())

    def _show_settings(self):
        from settings_ui import SettingsWindow
        SettingsWindow(self._root, on_settings_changed=self._on_settings_changed)

    def _on_settings_changed(self):
        """Called after settings window closes — re-apply live settings."""
        self._apply_clipboard_monitor()
        log.info("Settings reloaded")

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def _quit(self):
        log.info("Quitting LinkGuard")
        self._shutdown()
        self._root.quit()

    def _shutdown(self):
        if self._clipboard_mon:
            self._clipboard_mon.stop()
        if self._tray:
            self._tray.stop()
        self._lock_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
