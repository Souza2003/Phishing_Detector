"""
email_checker.py
Rule-based email phishing detection engine.
Analyses raw email text (headers + body) for phishing indicators.
"""

import re


# ── Urgency/threat phrases commonly used in phishing emails ──────────────────
URGENCY_PHRASES = [
    "your account has been suspended", "verify your account immediately",
    "unusual sign-in activity", "your account will be closed",
    "confirm your identity", "click here to verify",
    "update your payment information", "you have been selected",
    "act now", "limited time", "immediate action required",
    "your account is at risk", "unauthorised access",
    "we detected suspicious", "failure to respond",
    "your password has expired", "validate your account"
]

# ── Reward/prize bait phrases ─────────────────────────────────────────────────
REWARD_PHRASES = [
    "you have won", "congratulations", "claim your prize",
    "free gift", "you are a winner", "lucky winner",
    "unclaimed reward", "€1,000,000", "$1,000,000"
]

# ── Brands commonly impersonated in phishing emails ──────────────────────────
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google",
    "netflix", "hmrc", "revenue commissioners", "your bank",
    "dhl", "fedex", "ups", "linkedin", "dropbox"
]


def check_sender_domain_mismatch(headers: str, body: str) -> dict:
    """
    Checks if the From display name mentions a brand but the actual
    sending domain doesn't match that brand.
    e.g. From: PayPal Support <support@randomdomain.net>
    """
    from_match = re.search(r'From:.*?<(.+?)>', headers, re.IGNORECASE)
    if not from_match:
        return {"rule": "Sender Domain Mismatch", "triggered": False, "score": 0, "reason": None}

    sender_email = from_match.group(1).lower()
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
    from_line = headers[:headers.lower().find("\n", headers.lower().find("from:"))]

    for brand in IMPERSONATED_BRANDS:
        brand_in_display = brand in from_line.lower()
        brand_in_domain = brand.replace(" ", "") in sender_domain.replace("-", "").replace(".", "")
        if brand_in_display and not brand_in_domain:
            return {
                "rule": "Sender Domain Mismatch",
                "triggered": True,
                "score": 40,
                "reason": f"Email claims to be from '{brand}' but was sent from '{sender_domain}' — a common spoofing pattern."
            }
    return {"rule": "Sender Domain Mismatch", "triggered": False, "score": 0, "reason": None}


def check_urgency_language(body: str) -> dict:
    """Detects urgency and fear-based language used to pressure recipients."""
    body_lower = body.lower()
    found = [phrase for phrase in URGENCY_PHRASES if phrase in body_lower]
    if len(found) >= 2:
        return {"rule": "Urgency Language", "triggered": True, "score": 25,
                "reason": f"Email contains multiple urgency/threat phrases: \"{found[0]}\", \"{found[1]}\"."}
    elif len(found) == 1:
        return {"rule": "Urgency Language", "triggered": True, "score": 15,
                "reason": f"Email contains urgency/threat language: \"{found[0]}\"."}
    return {"rule": "Urgency Language", "triggered": False, "score": 0, "reason": None}


def check_reward_language(body: str) -> dict:
    """Detects prize/reward bait language."""
    body_lower = body.lower()
    found = [phrase for phrase in REWARD_PHRASES if phrase in body_lower]
    if found:
        return {"rule": "Reward/Prize Bait", "triggered": True, "score": 20,
                "reason": f"Email uses reward/prize language: \"{found[0]}\"."}
    return {"rule": "Reward/Prize Bait", "triggered": False, "score": 0, "reason": None}


def check_suspicious_links(body: str) -> dict:
    """
    Extracts URLs from body and checks for:
    - Mismatched anchor text vs actual URL
    - IP-based links
    - Suspicious TLDs in links
    """
    # Find all href links: <a href="URL">display text</a>
    html_links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    # Also find plain URLs
    plain_urls = re.findall(r'https?://[^\s<>"\']+', body)
    all_urls = list(set(html_links + plain_urls))

    suspicious = []
    for url in all_urls:
        if re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', url):
            suspicious.append(f"IP-based link: {url[:60]}")
        if any(tld in url.lower() for tld in [".tk", ".ml", ".ga", ".xyz", ".top", ".icu"]):
            suspicious.append(f"Suspicious TLD in link: {url[:60]}")

    if suspicious:
        return {"rule": "Suspicious Links in Body", "triggered": True, "score": 30,
                "reason": "Suspicious links detected: " + "; ".join(suspicious[:2])}

    if len(all_urls) > 5:
        return {"rule": "Excessive Links", "triggered": True, "score": 10,
                "reason": f"Email contains {len(all_urls)} links — unusually high for a legitimate email."}

    return {"rule": "Suspicious Links", "triggered": False, "score": 0, "reason": None}


def check_reply_to_mismatch(headers: str) -> dict:
    """
    Checks if Reply-To differs from the From address domain —
    a trick to collect replies on an attacker-controlled address.
    """
    from_match = re.search(r'From:.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', headers)
    reply_match = re.search(r'Reply-To:.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', headers, re.IGNORECASE)

    if not from_match or not reply_match:
        return {"rule": "Reply-To Mismatch", "triggered": False, "score": 0, "reason": None}

    from_domain = from_match.group(1).split("@")[-1].lower()
    reply_domain = reply_match.group(1).split("@")[-1].lower()

    if from_domain != reply_domain:
        return {
            "rule": "Reply-To Mismatch",
            "triggered": True,
            "score": 30,
            "reason": f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — replies go to a different server."
        }
    return {"rule": "Reply-To Mismatch", "triggered": False, "score": 0, "reason": None}


def check_generic_greeting(body: str) -> dict:
    """Phishing emails often use generic greetings rather than your actual name."""
    generic = ["dear customer", "dear user", "dear account holder",
               "dear valued member", "hello user", "dear sir/madam",
               "to whom it may concern", "dear friend"]
    body_lower = body.lower()
    found = [g for g in generic if g in body_lower]
    if found:
        return {"rule": "Generic Greeting", "triggered": True, "score": 10,
                "reason": f"Email uses a generic greeting ('{found[0]}') rather than your name."}
    return {"rule": "Generic Greeting", "triggered": False, "score": 0, "reason": None}


def check_attachment_mention(body: str) -> dict:
    """Flags mentions of attachments combined with urgency — common in malware delivery."""
    has_attachment_mention = bool(re.search(
        r'\b(open|download|view|see)\b.{0,30}\b(attachment|document|invoice|file|pdf|zip)\b',
        body, re.IGNORECASE
    ))
    if has_attachment_mention:
        return {"rule": "Suspicious Attachment Reference", "triggered": True, "score": 15,
                "reason": "Email urges you to open/download an attachment — a common malware delivery method."}
    return {"rule": "Attachment Reference", "triggered": False, "score": 0, "reason": None}


def check_poor_grammar(body: str) -> dict:
    """
    Simple heuristic: counts obvious grammar red flags.
    Not a full grammar checker — just catches common phishing tells.
    """
    indicators = [
        r'\bkindly\b',                  # "Kindly click" — overly formal, common in non-native English phishing
        r'\bdear of\b',
        r'\bactually\b.{0,20}\bbank\b', # "actually your bank"
        r'\bwe are (writing|contacting) (to|you)\b',
        r'\byour (cooperation|compliance) is (required|needed)\b',
    ]
    found = sum(1 for p in indicators if re.search(p, body, re.IGNORECASE))
    if found >= 2:
        return {"rule": "Grammar Red Flags", "triggered": True, "score": 10,
                "reason": "Email contains multiple phrasing patterns common in phishing (e.g., 'kindly', formal compliance language)."}
    return {"rule": "Grammar", "triggered": False, "score": 0, "reason": None}


# ── Master analysis function ──────────────────────────────────────────────────

ALL_EMAIL_RULES = [
    lambda h, b: check_sender_domain_mismatch(h, b),
    lambda h, b: check_urgency_language(b),
    lambda h, b: check_reward_language(b),
    lambda h, b: check_suspicious_links(b),
    lambda h, b: check_reply_to_mismatch(h),
    lambda h, b: check_generic_greeting(b),
    lambda h, b: check_attachment_mention(b),
    lambda h, b: check_poor_grammar(b),
]


def analyse_email(raw_email: str) -> dict:
    """
    Splits raw email into headers and body, then runs all rules.
    Returns result dict with score, risk level, and triggered rules.
    """
    # Split headers from body (blank line separates them)
    if "\n\n" in raw_email:
        headers, body = raw_email.split("\n\n", 1)
    else:
        headers = raw_email
        body = raw_email  # fallback if no clear separation

    results = []
    total_score = 0

    for rule_fn in ALL_EMAIL_RULES:
        result = rule_fn(headers, body)
        results.append(result)
        total_score += result["score"]

    total_score = min(total_score, 100)

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
        "total_score": total_score,
        "risk_level": risk_level,
        "risk_colour": risk_colour,
        "triggered_rules": triggered_rules,
        "all_results": results
    }