"""
Clipboard monitor — polls for new URLs and fires a callback.
Uses win32clipboard for reliable Windows clipboard access.
"""
import re
import threading
import time
import logging
import ctypes
import ctypes.wintypes

log = logging.getLogger(__name__)

URL_RE = re.compile(
    r"https?://[^\s\"'<>\]\[(){}\|\\^`]+"
    r"|(?:www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}[^\s\"'<>]*)",
    re.IGNORECASE,
)

CF_UNICODETEXT = 13


def _get_clipboard_text() -> str | None:
    """Read clipboard text using win32 API directly (no extra import needed)."""
    try:
        import win32clipboard
        win32clipboard.OpenClipboard(None)
        try:
            if win32clipboard.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return win32clipboard.GetClipboardData(CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()
    except Exception:
        pass
    return None


class ClipboardMonitor(threading.Thread):
    """
    Background thread that polls the clipboard every 600ms.
    Calls `on_url(url)` when a new URL is detected.
    """

    def __init__(self, on_url, poll_interval: float = 0.6):
        super().__init__(daemon=True, name="ClipboardMonitor")
        self._on_url = on_url
        self._interval = poll_interval
        self._stop_event = threading.Event()
        self._last_text: str = ""
        self._last_reported_url: str = ""

    def run(self):
        log.info("Clipboard monitor started")
        while not self._stop_event.wait(self._interval):
            try:
                self._tick()
            except Exception as e:
                log.debug("Clipboard tick error: %s", e)
        log.info("Clipboard monitor stopped")

    def stop(self):
        self._stop_event.set()

    def _tick(self):
        text = _get_clipboard_text()
        if not text or text == self._last_text:
            return
        self._last_text = text

        # Find all URLs in the clipboard content
        urls = URL_RE.findall(text.strip())
        if not urls:
            return

        # Take the first (or only) URL; skip if same as last reported
        url = urls[0].rstrip(".,;:!?)")
        if url == self._last_reported_url:
            return

        self._last_reported_url = url
        log.debug("Clipboard URL detected: %s", url)
        try:
            self._on_url(url)
        except Exception as e:
            log.error("on_url callback error: %s", e)
