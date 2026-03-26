"""
url_checker.py
Rule-based URL phishing detection engine.
Each rule returns a dict with: triggered (bool), score (int), reason (str)
"""

import re
import urllib.parse
import tldextract

# ── Suspicious keywords often found in phishing URLs ──────────────────────────
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "payment", "password", "credential",
    "webscr", "ebayisapi", "click", "redirect"
]

# ── Well-known brands that are commonly spoofed ───────────────────────────────
BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "twitter",
    "dropbox", "bankofamerica", "chase", "hsbc", "barclays", "halifax"
]

# ── TLDs frequently abused in phishing campaigns ─────────────────────────────
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                   ".club", ".online", ".site", ".icu", ".buzz"]


def check_ip_address(url: str) -> dict:
    """Flags URLs using a raw IP instead of a domain name."""
    pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    triggered = bool(re.match(pattern, url))
    return {
        "rule": "IP Address Used",
        "triggered": triggered,
        "score": 30 if triggered else 0,
        "reason": "URL uses a raw IP address instead of a domain name." if triggered else None
    }


def check_url_length(url: str) -> dict:
    """Long URLs are a common phishing tactic to hide the real destination."""
    length = len(url)
    if length > 100:
        return {"rule": "Excessive URL Length", "triggered": True, "score": 20,
                "reason": f"URL is {length} characters long (>100 is suspicious)."}
    elif length > 75:
        return {"rule": "Long URL", "triggered": True, "score": 10,
                "reason": f"URL is {length} characters long (>75 is mildly suspicious)."}
    return {"rule": "URL Length", "triggered": False, "score": 0, "reason": None}


def check_subdomains(url: str) -> dict:
    """Excessive subdomains are used to mimic legitimate domains."""
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    if not subdomain:
        return {"rule": "Subdomain Count", "triggered": False, "score": 0, "reason": None}
    count = len(subdomain.split("."))
    if count >= 3:
        return {"rule": "Excessive Subdomains", "triggered": True, "score": 25,
                "reason": f"URL has {count} subdomain levels — often used to disguise phishing domains."}
    elif count == 2:
        return {"rule": "Multiple Subdomains", "triggered": True, "score": 10,
                "reason": f"URL has {count} subdomain levels — worth checking."}
    return {"rule": "Subdomain Count", "triggered": False, "score": 0, "reason": None}


def check_https(url: str) -> dict:
    """Absence of HTTPS is a basic but still relevant signal."""
    triggered = not url.lower().startswith("https")
    return {
        "rule": "No HTTPS",
        "triggered": triggered,
        "score": 15 if triggered else 0,
        "reason": "URL does not use HTTPS — connection is unencrypted." if triggered else None
    }


def check_phishing_keywords(url: str) -> dict:
    """Checks for common phishing-related keywords in the URL."""
    url_lower = url.lower()
    found = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if len(found) >= 2:
        return {"rule": "Phishing Keywords", "triggered": True, "score": 20,
                "reason": f"URL contains suspicious keywords: {', '.join(found)}."}
    elif len(found) == 1:
        return {"rule": "Phishing Keyword", "triggered": True, "score": 10,
                "reason": f"URL contains suspicious keyword: '{found[0]}'."}
    return {"rule": "Phishing Keywords", "triggered": False, "score": 0, "reason": None}


def check_brand_spoofing(url: str) -> dict:
    """
    Detects brand names appearing in subdomains or paths (not as the actual domain).
    e.g. paypal.fake-login.com — 'paypal' is in subdomain, not the real domain.
    """
    extracted = tldextract.extract(url)
    real_domain = extracted.domain.lower()
    full_url_lower = url.lower()

    for brand in BRAND_NAMES:
        if brand in full_url_lower and brand != real_domain:
            return {
                "rule": "Brand Spoofing",
                "triggered": True,
                "score": 35,
                "reason": f"Brand name '{brand}' appears in URL but is not the registered domain — classic spoofing pattern."
            }
    return {"rule": "Brand Spoofing", "triggered": False, "score": 0, "reason": None}


def check_suspicious_tld(url: str) -> dict:
    """Flags domains using TLDs commonly associated with phishing."""
    extracted = tldextract.extract(url)
    tld = f".{extracted.suffix.lower()}" if extracted.suffix else ""
    # Check against known suspicious TLDs
    for s_tld in SUSPICIOUS_TLDS:
        if tld == s_tld or tld.endswith(s_tld):
            return {"rule": "Suspicious TLD", "triggered": True, "score": 20,
                    "reason": f"Domain uses '{tld}' — a TLD frequently abused in phishing campaigns."}
    return {"rule": "Suspicious TLD", "triggered": False, "score": 0, "reason": None}


def check_special_characters(url: str) -> dict:
    """
    Flags unusual special characters in URLs.
    @ in URL can redirect to a different host. Multiple dashes are common in spoofed domains.
    """
    reasons = []
    score = 0
    if "@" in url:
        reasons.append("'@' symbol found — browser ignores everything before it, a known phishing trick.")
        score += 25
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    dash_count = domain.count("-")
    if dash_count >= 3:
        reasons.append(f"Domain contains {dash_count} hyphens — common in spoofed domains like 'secure-paypal-login.com'.")
        score += 15

    if reasons:
        return {"rule": "Suspicious Characters", "triggered": True, "score": score,
                "reason": " ".join(reasons)}
    return {"rule": "Suspicious Characters", "triggered": False, "score": 0, "reason": None}


def check_url_shortener(url: str) -> dict:
    """Detects known URL shortening services used to hide destination."""
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "shorte.st", "is.gd", "buff.ly", "rebrand.ly"]
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}".lower()
    triggered = any(s in domain for s in shorteners)
    return {
        "rule": "URL Shortener",
        "triggered": triggered,
        "score": 15 if triggered else 0,
        "reason": f"URL uses a shortening service ({domain}) — the real destination is hidden." if triggered else None
    }


# ── Master analysis function ──────────────────────────────────────────────────

ALL_RULES = [
    check_ip_address,
    check_url_length,
    check_subdomains,
    check_https,
    check_phishing_keywords,
    check_brand_spoofing,
    check_suspicious_tld,
    check_special_characters,
    check_url_shortener,
]


def analyse_url(url: str) -> dict:
    """
    Runs all rules against a URL.
    Returns a result dict with total score, risk level, and triggered rules.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # normalise for parsing

    results = []
    total_score = 0

    for rule_fn in ALL_RULES:
        result = rule_fn(url)
        results.append(result)
        total_score += result["score"]

    # Cap at 100
    total_score = min(total_score, 100)

    # Risk classification
    if total_score >= 60:
        risk_level = "HIGH"
        risk_colour = "red"
    elif total_score >= 30:
        risk_level = "MEDIUM"
        risk_colour = "orange"
    else:
        risk_level = "LOW"
        risk_colour = "green"

    triggered_rules = [r for r in results if r["triggered"]]

    return {
        "url": url,
        "total_score": total_score,
        "risk_level": risk_level,
        "risk_colour": risk_colour,
        "triggered_rules": triggered_rules,
        "all_results": results
    }