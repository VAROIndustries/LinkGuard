"""
Windows startup registry management and protocol handler registration.
Uses HKEY_CURRENT_USER — no admin rights required.
"""
import sys
import os
import winreg
import logging
from pathlib import Path

log = logging.getLogger(__name__)

APP_NAME = "PhishUrl"
# When frozen with PyInstaller, sys.executable is the .exe; otherwise use the script path
EXE_PATH = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])


# ── Windows Startup ───────────────────────────────────────────────────────────

STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def is_startup_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY) as k:
            val, _ = winreg.QueryValueEx(k, APP_NAME)
            return bool(val)
    except FileNotFoundError:
        return False


def enable_startup():
    cmd = f'"{EXE_PATH}"'
    if not EXE_PATH.endswith(".exe"):
        # Running as a .py script — launch via pythonw for no console window
        pythonw = Path(sys.executable).parent / "pythonw.exe"
        cmd = f'"{pythonw}" "{EXE_PATH}"'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY,
                        access=winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, cmd)
    log.info("Startup enabled: %s", cmd)


def disable_startup():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_KEY,
                            access=winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, APP_NAME)
        log.info("Startup disabled")
    except FileNotFoundError:
        pass


# ── Protocol Handler ──────────────────────────────────────────────────────────
# We register under HKCU\Software\Classes which overrides HKCR per-user
# and does NOT require administrator privileges.

PROTO_BASE = r"Software\Classes"
SCHEMES = ("http", "https")


def is_protocol_handler_enabled() -> bool:
    try:
        key_path = rf"{PROTO_BASE}\http\shell\open\command"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            val, _ = winreg.QueryValueEx(k, "")
            return EXE_PATH.lower() in val.lower() or "phishurl" in val.lower()
    except FileNotFoundError:
        return False


def enable_protocol_handler() -> bool:
    """
    Register PhishUrl as the http/https handler in HKCU.
    Saves the existing handler command so we can forward URLs to the real browser.
    Returns True on success.
    """
    real_cmd = _get_current_handler("http")
    if real_cmd and (EXE_PATH.lower() in real_cmd.lower() or "phishurl" in real_cmd.lower()):
        # Already us — nothing to do
        return True

    # Save original browser command so we can forward to it
    if real_cmd:
        _save_original_browser(real_cmd)

    cmd = f'"{EXE_PATH}" "%1"'
    if not EXE_PATH.endswith(".exe"):
        pythonw = Path(sys.executable).parent / "pythonw.exe"
        cmd = f'"{pythonw}" "{os.path.abspath(sys.argv[0])}" "%1"'

    try:
        for scheme in SCHEMES:
            _write_proto_key(scheme, cmd)
        log.info("Protocol handler enabled")
        return True
    except Exception as e:
        log.error("Failed to enable protocol handler: %s", e)
        return False


def disable_protocol_handler():
    """Remove our HKCU protocol handler overrides, restoring system default."""
    for scheme in SCHEMES:
        try:
            key_path = rf"{PROTO_BASE}\{scheme}"
            _delete_key_tree(winreg.HKEY_CURRENT_USER, key_path)
        except Exception as e:
            log.warning("Could not remove %s handler: %s", scheme, e)
    log.info("Protocol handler disabled — system default restored")


def get_real_browser_cmd() -> str:
    """Return the stored original browser command for URL forwarding."""
    from database import get_setting
    return get_setting("real_browser_cmd")


def open_in_real_browser(url: str):
    """Forward a URL to the real browser (bypassing our handler)."""
    import subprocess
    cmd = get_real_browser_cmd()
    if cmd:
        # Replace %1 placeholder with actual URL
        final = cmd.replace("%1", url).replace('""', '"')
        try:
            subprocess.Popen(final, shell=True)
            return
        except Exception as e:
            log.error("Failed to launch real browser: %s", e)
    # Fallback: use os.startfile which goes through the system default
    # (which could loop back to us if we're still registered — use webbrowser module instead)
    import webbrowser
    # Temporarily we use the default handler for the url — this may loop if still registered.
    # Best effort: try known browsers directly.
    _launch_fallback_browser(url)


def _launch_fallback_browser(url: str):
    import subprocess
    browsers = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for b in browsers:
        if os.path.exists(b):
            subprocess.Popen([b, url])
            return
    # Last resort
    import webbrowser
    webbrowser.open(url)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_current_handler(scheme: str) -> str:
    """Read the current (effective) command for an URL scheme."""
    # Check HKCU override first, then HKCR
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_CLASSES_ROOT):
        try:
            base = rf"{PROTO_BASE}\{scheme}" if hive == winreg.HKEY_CURRENT_USER else scheme
            key_path = rf"{base}\shell\open\command"
            with winreg.OpenKey(hive, key_path) as k:
                val, _ = winreg.QueryValueEx(k, "")
                if val:
                    return val
        except FileNotFoundError:
            continue
    return ""


def _save_original_browser(cmd: str):
    from database import set_setting, get_setting
    existing = get_setting("real_browser_cmd")
    if not existing:
        set_setting("real_browser_cmd", cmd)


def _write_proto_key(scheme: str, open_cmd: str):
    base = rf"{PROTO_BASE}\{scheme}"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, f"URL:{scheme.upper()} Protocol")
        winreg.SetValueEx(k, "URL Protocol", 0, winreg.REG_SZ, "")
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,
                             rf"{base}\shell\open\command") as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, open_cmd)


def _delete_key_tree(hive, path: str):
    """Recursively delete a registry key and all subkeys."""
    try:
        with winreg.OpenKey(hive, path, access=winreg.KEY_READ) as k:
            while True:
                try:
                    subkey = winreg.EnumKey(k, 0)
                    _delete_key_tree(hive, rf"{path}\{subkey}")
                except OSError:
                    break
        winreg.DeleteKey(hive, path)
    except FileNotFoundError:
        pass
