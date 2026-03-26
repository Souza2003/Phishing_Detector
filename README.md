# Phishing_Detector

# 🎣 Phishing Detection Tool

A rule-based phishing detection tool for URLs and emails, built with Python and Streamlit.

> Built by **Ruth Dsouza**

---

## Features

- **URL Checker** — 9 detection rules including IP detection, brand spoofing, suspicious TLDs, URL shorteners, and more
- **Email Checker** — 8 detection rules including sender domain mismatch, urgency language, reply-to mismatch, and suspicious links
- **Risk scoring** — each triggered rule adds to a 0–100 risk score with LOW / MEDIUM / HIGH classification
- **Clean dashboard** — Streamlit web UI with example test cases built in

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
streamlit run app.py
```

Then open **http://localhost:8501** in your browser.

---

## Project Structure

```
phishing_detector/
├── app.py              # Streamlit dashboard (UI)
├── url_checker.py      # URL detection engine (9 rules)
├── email_checker.py    # Email detection engine (8 rules)
├── requirements.txt    # Python dependencies
└── README.md
```

---

## 🧪 Test Examples

### 🔗 URL Examples

#### 🔴 High Risk URLs (score 60–100)

```
http://paypal-secure-login.tk/verify?account=user&confirm=password
```
*Triggers: Brand spoofing (PayPal), suspicious TLD (.tk), no HTTPS, phishing keywords*

```
http://192.168.1.1/apple/id/verify?token=abc123
```
*Triggers: Raw IP address, no HTTPS, brand spoofing (Apple), phishing keywords*

```
http://secure.login.update.confirm.amazon.fake-domain.xyz/signin
```
*Triggers: Excessive subdomains, brand spoofing (Amazon), suspicious TLD (.xyz), phishing keywords*

```
http://microsoft-account-verify-update-login.com/confirm?user=victim@email.com
```
*Triggers: Brand spoofing, excessive URL length, phishing keywords, multiple hyphens*

---

#### 🟡 Medium Risk URLs (score 30–59)

```
http://amazon-account.support/signin
```
*Triggers: No HTTPS, brand spoofing attempt, phishing keyword*

```
http://bit.ly/3xR9kLm
```
*Triggers: URL shortener (destination hidden), no HTTPS*

```
http://secure-login-portal.com/account/verify
```
*Triggers: No HTTPS, phishing keywords, multiple hyphens in domain*

```
http://update-your-payment.net/billing
```
*Triggers: No HTTPS, phishing keywords (update, payment)*

---

#### 🟢 Low Risk URLs (score 0–29)

```
https://www.bbc.co.uk/news
```
```
https://github.com/torvalds/linux
```
```
https://www.google.com/search?q=python+tutorial
```
```
https://www.linkedin.com/in/yourprofile
```

---

### 📧 Email Examples

#### 🔴 High Risk Email

```
From: PayPal Support <security@random-mailer99.net>
Reply-To: collect@attacker-domain.ru
Subject: Your account has been suspended - Immediate action required

Dear Customer,

We have detected suspicious activity on your PayPal account. Your account has been suspended due to unusual sign-in activity.

Kindly verify your account immediately by clicking the link below or your account will be closed within 24 hours.

Click here to verify: http://192.168.1.1/paypal/confirm?user=victim

Please open the attached document to complete your verification.

Failure to respond within 24 hours will result in permanent suspension.

PayPal Security Team
```
*Triggers: Sender domain mismatch, reply-to mismatch, urgency language, suspicious IP link, generic greeting, attachment reference*

---

#### 🟡 Medium Risk Email

```
From: Netflix Billing <billing@netflix-update.info>
Subject: Your payment failed - update required

Dear User,

Your recent payment for Netflix did not go through. Please update your payment information to avoid interruption to your service.

Click here to update: https://netflix-billing-update.info/payment

Netflix Support Team
```
*Triggers: Sender domain mismatch, generic greeting, phishing keyword in link*

---

#### 🟢 Low Risk Email

```
From: GitHub Notifications <noreply@github.com>
Subject: Your pull request has been merged

Hi Sarah,

Your pull request "Fix login bug" has been successfully merged into the main branch of the repository my-project.

You can view the changes at: https://github.com/sarah/my-project/pull/42

Thanks for contributing!

The GitHub Team
```
*Clean: Sender domain matches brand, no urgency language, personalised greeting, legitimate link*

---

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 LOW | 0–29 | Likely safe — no significant phishing indicators |
| 🟡 MEDIUM | 30–59 | Suspicious — treat with caution |
| 🔴 HIGH | 60–100 | Likely phishing — do not click or respond |

---

## Detection Rules

### URL Rules
| Rule | Score |
|------|-------|
| Brand Spoofing | +35 |
| IP Address Used | +30 |
| Excessive Subdomains | +25 |
| Special Characters (@, hyphens) | +25 |
| Phishing Keywords (2+) | +20 |
| Suspicious TLD (.tk, .xyz etc.) | +20 |
| Excessive URL Length (>100 chars) | +20 |
| No HTTPS | +15 |
| URL Shortener | +15 |

### Email Rules
| Rule | Score |
|------|-------|
| Sender Domain Mismatch | +40 |
| Reply-To Mismatch | +30 |
| Suspicious Links in Body | +30 |
| Urgency Language (2+ phrases) | +25 |
| Reward/Prize Bait | +20 |
| Urgency Language (1 phrase) | +15 |
| Suspicious Attachment Reference | +15 |
| Generic Greeting | +10 |
| Grammar Red Flags | +10 |

---

## Built With
- Python 3.10+
- [Streamlit](https://streamlit.io/)
- [tldextract](https://github.com/john-kurkowski/tldextract)
- `re` and `urllib` (Python standard library)
