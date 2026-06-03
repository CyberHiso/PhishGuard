# PhishGuard — Phishing Email Detector

A command-line tool that analyzes email content for phishing indicators and produces a color-coded risk report. Built entirely in Python, runs fully offline, no API keys required.

---

## Features

- **Header Analysis** — detects spoofed senders, From/Reply-To mismatches, Return-Path inconsistencies, failed SPF/DKIM signals, suspicious sending domains, and bulk-mailer fingerprints
- **URL Analysis** — extracts every URL from the email body and checks for IP-based hosts, deceptive anchor text, suspicious TLDs (`.tk`, `.xyz`, `.ru`, etc.), URL shorteners, excessive subdomains, and obfuscated characters
- **Body Analysis** — scans for urgency language, credential harvesting phrases, social engineering lures, action prompts, and impersonation indicators using regex pattern matching
- **Weighted Risk Scoring** — combines findings across all three categories into a 0–100 score with severity weighting (HIGH/MEDIUM/LOW)
- **Color-coded Terminal Report** — clear, readable output with risk level (LOW / MEDIUM / HIGH / CRITICAL) and per-finding breakdown
- **Dual Input Modes** — analyze a `.eml` or `.txt` file, or paste raw email text interactively
- **Fully Offline** — no external API calls, no network requests, no data leaves your machine

---

## Project Structure

```
PhishGuard/
├── phishguard.py               # Main entry point & report renderer
├── analyzers/
│   ├── header_analyzer.py      # Email header inspection
│   ├── url_analyzer.py         # URL extraction & analysis
│   └── body_analyzer.py        # Body keyword & pattern scanning
├── utils/
│   └── scorer.py               # Risk scoring & verdict logic
├── samples/
│   ├── phishing1.eml           # Sample: credential phish (PayPal spoof)
│   ├── phishing2.eml           # Sample: IT helpdesk spear-phish
│   └── legitimate.eml          # Sample: genuine GitHub notification
├── requirements.txt
└── README.md
```

---

## Installation

**Requirements:** Python 3.10 or higher

1. Clone or download this repository:
   ```bash
   git clone https://github.com/yourusername/PhishGuard.git
   cd PhishGuard
   ```

2. Install the single dependency:
   ```bash
   pip install -r requirements.txt
   ```

That's it. No API keys, no configuration files, no internet connection needed.

---

## Usage

### Analyze an email file (`.eml` or `.txt`)
```bash
python phishguard.py samples/phishing1.eml
python phishguard.py samples/phishing2.eml
python phishguard.py samples/legitimate.eml
```

### Interactive paste mode (no file needed)
```bash
python phishguard.py
```
Paste raw email headers + body, then type `END` on its own line to submit.

### Debug: show extracted body text
```bash
python phishguard.py samples/phishing1.eml --show-body
```

---

## Sample Output

Running against `samples/phishing1.eml`:

```
======================================================
       PHISHGUARD - EMAIL ANALYZER
======================================================

  Risk Score : 100/100
  Risk Level : CRITICAL

  Finding Summary
  --------------------------------------------------
   HIGH   : 8
   MEDIUM : 3
   LOW    : 2
   TOTAL  : 13

  HEADER ANALYSIS
  --------------------------------------------------
   [!] [HIGH  ] From/Reply-To mismatch — From: security@paypal-secure-verify.xyz | Reply-To: attacker-collect@gmail.com
   [!] [HIGH  ] Display name "paypal security" impersonates "paypal" but sending domain is "paypal-secure-verify.xyz"
   [!] [HIGH  ] SPF check failed — sending server is not authorized to send for this domain
   [!] [HIGH  ] DKIM signature verification failed — email may have been tampered with
   [!] [MEDIUM] X-Mailer header suggests bulk/automated sending tool: "PHPMailer 6.4.1"

  URL ANALYSIS
  --------------------------------------------------
   [!] [HIGH  ] Misleading link text — displayed: "https://www.paypal.com/verify" | actual URL: http://paypal.account-secure.verify.xyz/login?token=abc123
   [!] [HIGH  ] Brand "paypal" used as subdomain to impersonate: http://paypal.account-secure.verify.xyz/login?token=abc123
   [!] [MEDIUM] Suspicious TLD ".xyz" in URL: http://paypal.account-secure.verify.xyz/login?token=abc123
   [!] [MEDIUM] Unencrypted HTTP used for sensitive-looking page: http://paypal.account-secure.verify.xyz/login?token=abc123

  BODY ANALYSIS
  --------------------------------------------------
   [!] [HIGH  ] Urgency/pressure phrase detected: "your account will be suspended"
   [!] [HIGH  ] Urgency/pressure phrase detected: "failure to respond"
   [!] [HIGH  ] Credential request phrase detected: "confirm your identity"
   [!] [HIGH  ] Credential request phrase detected: "social security number"
   [!] [MEDIUM] Social engineering lure phrase detected: "unusual activity"
   [!] [LOW   ] Impersonation indicator in body: "dear valued customer,"

  VERDICT:
   This email shows strong, multiple indicators of phishing.
   Do NOT click any links or open attachments.

======================================================
```

> **Note:** The output above is rendered in color in the terminal — HIGH findings appear in red, MEDIUM in yellow, LOW in cyan, and a CRITICAL verdict displays in bright red.

---

## How the Scoring Works

Each finding is assigned a severity level when detected:

| Severity | Points |
|----------|--------|
| HIGH     | 18     |
| MEDIUM   | 10     |
| LOW      | 4      |

The total score is capped at 100. The risk level thresholds are:

| Score Range | Risk Level |
|-------------|------------|
| 75 – 100    | CRITICAL   |
| 50 – 74     | HIGH       |
| 25 – 49     | MEDIUM     |
| 0  – 24     | LOW        |

---

## Detection Coverage

### Headers
| Check | Severity |
|-------|----------|
| From / Reply-To mismatch | HIGH |
| Display name impersonates brand | HIGH |
| SPF fail / softfail | HIGH / MEDIUM |
| DKIM failure | HIGH |
| Return-Path domain mismatch | MEDIUM |
| Bulk mailer X-Mailer header | MEDIUM |
| No DKIM signature | LOW |
| X-Originating-IP exposed | LOW |

### URLs
| Check | Severity |
|-------|----------|
| IP address as URL host | HIGH |
| Misleading anchor display text | HIGH |
| Brand name in subdomain | HIGH |
| Suspicious TLD | MEDIUM |
| URL shortener | MEDIUM |
| Unencrypted HTTP on sensitive page | MEDIUM |
| Excessive subdomains (3+) | MEDIUM |
| Suspicious keywords in path | LOW |
| URL-encoded obfuscation | LOW |

### Body
| Check | Severity |
|-------|----------|
| Urgency / account suspension phrases | HIGH |
| Credential request phrases | HIGH |
| JavaScript in email body | HIGH |
| Action prompts (click here, open attachment) | MEDIUM |
| Social engineering lures | MEDIUM |
| Impersonation language | LOW |
| Base64 obfuscation blocks | LOW |

---

## Limitations

- This tool performs **static, offline analysis** only. It does not visit URLs, sandbox attachments, or query reputation databases.
- A LOW score does not guarantee an email is safe — sophisticated phishing can evade pattern-based detection.
- The tool is not a replacement for a full email security gateway.

---

## Disclaimer

> This project was built for **educational and portfolio purposes** to demonstrate Python-based security tooling, email parsing, regex pattern matching, and CLI application design. It is intended for use in authorized environments only (analyzing your own email samples, cybersecurity coursework, CTF practice, or security awareness training). The author is not responsible for any misuse of this tool.

---

## License

MIT License — free to use, modify, and distribute with attribution.
