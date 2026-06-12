"""
URL risk checker — heuristics + optional API verification.
Returns a RiskResult with score (0-100), level, and reasons.
"""
from __future__ import annotations

import re
import hashlib
import ipaddress
import logging
import json
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote
from typing import Optional
import requests

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".ws", ".pw", ".cc", ".su", ".icu",
    ".rest", ".cam", ".buzz", ".monster", ".cyou",
}

# Well-known brands commonly impersonated
BRAND_KEYWORDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "bankofamerica",
    "chase", "wellsfargo", "citibank", "usbank", "steam", "discord",
    "dropbox", "icloud", "outlook", "office365", "onedrive", "adobe",
    "ebay", "walmart", "target", "irs", "fedex", "ups", "dhl",
    "coinbase", "binance", "blockchain", "metamask",
}

SUSPICIOUS_PATH_WORDS = {
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "confirm", "confirmation",
    "secure", "security", "update", "account", "password", "passwd",
    "banking", "wallet", "recover", "recovery", "support", "helpdesk",
    "invoice", "payment", "billing", "checkout",
}

# Homoglyph map (digits/lookalikes → letters they mimic)
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
    "vv": "w", "rn": "m",
}

# URL shorteners (redirect through, we can't check the final target without following)
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.io", "rebrand.ly", "cutt.ly", "rb.gy", "is.gd", "v.gd",
    "tiny.cc", "lnkd.in", "adf.ly", "bc.vc",
}


# ── Data ──────────────────────────────────────────────────────────────────────

@dataclass
class RiskResult:
    url: str
    domain: str
    score: int                      # 0–100
    level: str                      # clean | suspicious | phishing
    reasons: list[str] = field(default_factory=list)
    api_checked: bool = False

    @property
    def color(self) -> str:
        return {"clean": "#27ae60", "suspicious": "#f39c12", "phishing": "#e74c3c"}.get(
            self.level, "#95a5a6"
        )

    @property
    def emoji(self) -> str:
        return {"clean": "✅", "suspicious": "⚠️", "phishing": "🚨"}.get(self.level, "❓")


def score_to_level(score: int) -> str:
    if score >= 55:
        return "phishing"
    if score >= 22:
        return "suspicious"
    return "clean"


# ── Main check ────────────────────────────────────────────────────────────────

def check_url(url: str, gsb_key: str = "", vt_key: str = "") -> RiskResult:
    """Full URL risk check. Returns RiskResult."""
    url = url.strip()

    # Normalize — add scheme if missing
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return RiskResult(url=url, domain="", score=0, level="clean",
                          reasons=["Could not parse URL"])

    domain = parsed.hostname or ""
    score = 0
    reasons: list[str] = []

    # ── Heuristic checks ──────────────────────────────────────────────────────

    # 1. IP address as host
    if _is_ip(domain):
        score += 40
        reasons.append("Domain is a raw IP address")

    # 2. Suspicious TLD
    tld = _get_tld(domain)
    if tld in SUSPICIOUS_TLDS:
        score += 18
        reasons.append(f"High-risk TLD: {tld}")

    # 3. Homoglyph / typosquat
    hg = _homoglyph_brand(domain)
    if hg:
        score += 35
        reasons.append(f"Domain mimics brand '{hg}' using lookalike characters")

    # 4. Brand keyword in non-root domain position
    brand_abuse = _brand_in_subdomain(domain)
    if brand_abuse:
        score += 30
        reasons.append(f"Brand name '{brand_abuse}' used in subdomain to impersonate")

    # 5. Brand name embedded in second-level domain label (e.g. bankofamerica-secure.tk)
    parts = domain.split(".")
    sld = parts[-2] if len(parts) >= 2 else domain
    for brand in BRAND_KEYWORDS:
        if brand in sld.lower() and sld.lower() != brand:
            score += 22
            reasons.append(f"Brand name '{brand}' embedded in domain label (possible impersonation)")
            break

    # 6. Excessive subdomains (e.g. login.paypal.com.evilsite.ru)
    if len(parts) > 4:
        score += 15
        reasons.append(f"Excessive subdomain depth ({len(parts) - 2} subdomains)")

    # 6. Punycode / IDN homograph
    if "xn--" in domain:
        score += 22
        reasons.append("Internationalized domain (possible IDN homograph attack)")

    # 7. @ symbol in URL (credential phishing trick: user@evil.com)
    if "@" in parsed.netloc:
        score += 35
        reasons.append("URL contains '@' in host (credential embedding trick)")

    # 8. Multiple hyphens in domain label
    for label in domain.split("."):
        if label.count("-") >= 3:
            score += 10
            reasons.append(f"Suspicious hyphenation in domain label: {label}")
            break

    # 9. Suspicious path keywords
    path_lower = unquote(parsed.path).lower()
    query_lower = (parsed.query or "").lower()
    combined = path_lower + " " + query_lower
    hits = [w for w in SUSPICIOUS_PATH_WORDS if w in combined]
    if len(hits) >= 2:
        score += 12
        reasons.append(f"Suspicious path keywords: {', '.join(hits[:4])}")
    elif len(hits) == 1:
        score += 5

    # 10. URL shortener (can't inspect final destination without following)
    if domain.lstrip("www.") in URL_SHORTENERS:
        score += 22
        reasons.append(f"URL shortener detected ({domain}) — final destination hidden")

    # 11. Excessive URL length
    if len(url) > 150:
        score += 8
        reasons.append(f"Unusually long URL ({len(url)} chars)")

    # 12. HTTP (not HTTPS) for a sensitive-looking page
    if parsed.scheme == "http" and hits:
        score += 8
        reasons.append("Unencrypted HTTP with sensitive keywords in path")

    # 13. Multiple redirects in URL (e.g. ?url=http://...)
    redirect_params = re.findall(
        r'(?:url|redirect|redir|next|forward|goto|link|target)=https?', url, re.I
    )
    if redirect_params:
        score += 15
        reasons.append("URL contains open redirect parameter")

    # 14. Data URI
    if url.startswith("data:"):
        score += 60
        reasons.append("Data URI — commonly used in phishing HTML attachments")

    score = min(score, 100)
    level = score_to_level(score)
    result = RiskResult(url=url, domain=domain, score=score, level=level, reasons=reasons)

    # ── Optional API checks ───────────────────────────────────────────────────
    if gsb_key:
        try:
            _check_google_safe_browsing(url, gsb_key, result)
        except Exception as e:
            log.warning("GSB check failed: %s", e)

    if vt_key and result.level != "phishing":
        try:
            _check_virustotal(url, vt_key, result)
        except Exception as e:
            log.warning("VirusTotal check failed: %s", e)

    return result


# ── API checks ────────────────────────────────────────────────────────────────

def _check_google_safe_browsing(url: str, api_key: str, result: RiskResult):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "linkguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp = requests.post(endpoint, json=payload, timeout=5)
    if resp.status_code == 200:
        data = resp.json()
        if data.get("matches"):
            threat = data["matches"][0].get("threatType", "THREAT")
            result.score = min(result.score + 50, 100)
            result.level = "phishing"
            result.reasons.insert(0, f"Google Safe Browsing: {threat}")
            result.api_checked = True


def _check_virustotal(url: str, api_key: str, result: RiskResult):
    url_id = hashlib.sha256(url.encode()).hexdigest()
    headers = {"x-apikey": api_key}
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers, timeout=8
    )
    if resp.status_code == 200:
        stats = (resp.json().get("data", {})
                 .get("attributes", {})
                 .get("last_analysis_stats", {}))
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious >= 3:
            result.score = min(result.score + 45, 100)
            result.level = "phishing"
            result.reasons.insert(0, f"VirusTotal: {malicious} engines flagged malicious")
            result.api_checked = True
        elif malicious >= 1 or suspicious >= 2:
            result.score = min(result.score + 20, 100)
            if result.level == "clean":
                result.level = "suspicious"
            result.reasons.insert(0, f"VirusTotal: {malicious} malicious, {suspicious} suspicious")
            result.api_checked = True


# ── Heuristic helpers ─────────────────────────────────────────────────────────

def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return "." + parts[-1]
    return ""


def _homoglyph_brand(domain: str) -> Optional[str]:
    """Check if domain is a homoglyph impersonation of a known brand."""
    # Remove TLD for brand comparison
    parts = domain.split(".")
    label = parts[-2] if len(parts) >= 2 else domain

    # Normalize: replace common homoglyphs
    normalized = label.lower()
    for glyph, letter in HOMOGLYPHS.items():
        normalized = normalized.replace(glyph, letter)

    for brand in BRAND_KEYWORDS:
        # Direct match after normalization (different from original means homoglyph used)
        if normalized == brand and label.lower() != brand:
            return brand
        # Levenshtein distance ≤ 1 for typosquatting
        if label.lower() != brand and _levenshtein(normalized, brand) <= 1 and len(brand) >= 5:
            return brand
    return None


def _brand_in_subdomain(domain: str) -> Optional[str]:
    """Detect brand name used in subdomain to impersonate (e.g. paypal.evil.com)."""
    parts = domain.split(".")
    if len(parts) < 3:
        return None
    # Check subdomains (everything except the last two labels)
    subdomains = ".".join(parts[:-2]).lower()
    for brand in BRAND_KEYWORDS:
        if brand in subdomains:
            return brand
    return None


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]
