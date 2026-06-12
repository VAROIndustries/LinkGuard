# PhishUrl

A Windows system tray application that silently monitors URLs — from your clipboard and every link you click — and warns you before a phishing page can load.

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue)
![Platform Windows](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License MIT](https://img.shields.io/badge/License-MIT-green)

---

## Features

- **Clipboard monitoring** — detects URLs as soon as you copy them
- **Link interception** — optionally registers as the system `http`/`https` handler so every clicked link is checked first (no admin required)
- **Heuristic analysis** — scores URLs across 12+ risk signals without needing any API key
- **API integration** — optional Google Safe Browsing and VirusTotal checks
- **Whitelist / Blacklist** — one-click to always allow or always block a domain
- **History** — log of every URL checked with score and action taken
- **Starts with Windows** — configurable from the Settings window
- **No console window** — runs silently in the background via the system tray

---

## Risk Signals

| Signal | Score |
|---|---|
| Raw IP address as hostname | +40 |
| `@` in URL (credential embedding trick) | +35 |
| Homoglyph / typosquat (`paypa1.com`) | +35 |
| Brand name in subdomain (`paypal.evil.com`) | +30 |
| Brand name embedded in domain label (`bankofamerica-secure.tk`) | +22 |
| IDN punycode domain (`xn--`) | +22 |
| URL shortener (final destination hidden) | +22 |
| High-risk TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, …) | +18 |
| Open redirect parameter | +15 |
| Excessive subdomain depth | +15 |
| Suspicious path keywords (login, verify, account, …) | +5–12 |
| Unencrypted HTTP + sensitive path | +8 |

**Risk levels:** Clean (0–21) · Suspicious (22–54) · Phishing (55+)

---

## Installation

**Requirements:** Python 3.12 · Windows 10/11

```
git clone https://github.com/VAROIndustries/PhishUrl.git
cd PhishUrl
pip install -r requirements.txt
```

**Run (no console window):**

```
pythonw PhishUrl.pyw
```

Or double-click `PhishUrl.pyw` in Explorer.

**Build a standalone `.exe`:**

```
build.bat
```

---

## Usage

After launching, a shield icon appears in the system tray.

| Tray action | Description |
|---|---|
| Left-click | (no action — right-click for menu) |
| **Check a URL…** | Manually paste and check any URL |
| **Settings…** | Open the settings window |
| **Pause monitoring** | Temporarily stop clipboard checks |
| **Quit** | Exit the application |

### Alert dialog

When a suspicious or phishing URL is detected you'll see a popup showing the risk level, score bar, and the specific findings. You can:

- **Open anyway** — visit the URL this one time
- **Always allow** — add the domain to your whitelist (never prompted again)
- **Block domain** — add to blacklist (silently blocked going forward)
- **Dismiss** — do nothing

### Link interception (protocol handler)

Enable **"Intercept all http/https link clicks"** in Settings → General. PhishUrl will register itself as the system URL handler under `HKEY_CURRENT_USER` (no administrator rights needed). Every link you click in any application will be checked before your browser opens it.

To disable, uncheck the same setting and your previous default browser is restored automatically.

---

## Settings

| Setting | Description |
|---|---|
| Start with Windows | Adds an entry to `HKCU\...\Run` |
| Monitor clipboard | Polls clipboard every 600 ms |
| Intercept link clicks | Registers as http/https protocol handler |
| Risk threshold | Alert at *Suspicious & above* or *Phishing only* |
| Google Safe Browsing key | Free — 10,000 requests/day |
| VirusTotal key | Free — 4 requests/minute |

### Adding API keys

Both APIs are optional. Heuristic checks run without any keys.

- **Google Safe Browsing:** [console.cloud.google.com](https://console.cloud.google.com) → enable Safe Browsing API → create an API key
- **VirusTotal:** [virustotal.com](https://www.virustotal.com) → sign up → My API key

Keys are stored locally in `%APPDATA%\PhishUrl\phishurl.db` and never sent anywhere except the respective API endpoint.

---

## Data & Privacy

All data stays on your machine:

- **Database:** `%APPDATA%\PhishUrl\phishurl.db` — whitelist, blacklist, history, settings
- **Log:** `%APPDATA%\PhishUrl\phishurl.log`
- **No telemetry.** URLs are only sent externally if you configure a Google Safe Browsing or VirusTotal API key.

---

## License

MIT
