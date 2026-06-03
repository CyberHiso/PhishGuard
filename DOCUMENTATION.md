# PhishGuard — Full Project Documentation

> **Purpose of this document:** A complete technical and narrative record of the PhishGuard
> phishing email detector — what it does, how it was built, how every component works,
> and how to use it. Written for portfolio presentation, interviews, and future development.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [What We Built — Development Journey](#2-what-we-built--development-journey)
3. [Project Structure](#3-project-structure)
4. [Architecture & Data Flow](#4-architecture--data-flow)
5. [Component Deep-Dives](#5-component-deep-dives)
   - 5.1 [Header Analyzer](#51-header-analyzer)
   - 5.2 [URL Analyzer](#52-url-analyzer)
   - 5.3 [Body Analyzer](#53-body-analyzer)
   - 5.4 [Scoring Engine](#54-scoring-engine)
   - 5.5 [Threat Classifier](#55-threat-classifier)
   - 5.6 [PDF Exporter](#56-pdf-exporter)
   - 5.7 [CLI Entry Point](#57-cli-entry-point)
   - 5.8 [GUI](#58-gui)
6. [Detection Coverage Reference](#6-detection-coverage-reference)
7. [Threat Classification Reference](#7-threat-classification-reference)
8. [Scoring System Explained](#8-scoring-system-explained)
9. [Usage Guide](#9-usage-guide)
10. [Sample Outputs](#10-sample-outputs)
11. [Dependencies](#11-dependencies)
12. [Design Decisions & Trade-offs](#12-design-decisions--trade-offs)
13. [Known Limitations](#13-known-limitations)
14. [Potential Future Enhancements](#14-potential-future-enhancements)
15. [Disclaimer](#15-disclaimer)

---

## 1. Project Overview

**PhishGuard** is a fully offline, Python-based phishing email analysis tool. It accepts a
raw email (either as a `.eml` / `.txt` file or pasted text), parses it, and runs three
independent analyzers against the headers, URLs, and body content. The findings are combined
into a weighted risk score, a threat classification label, and a detailed report that can be
viewed in the terminal, in a modern GUI, or exported as a PDF.

### Goals

| Goal | How It Is Met |
|------|--------------|
| Detect phishing indicators statically | Three analyzer modules with 25+ individual checks |
| Work without internet / API keys | 100% offline regex and heuristic logic |
| Be useful for learning | Heavy inline comments, clear module separation |
| Look professional in a portfolio | Color-coded terminal output, CustomTkinter GUI, PDF reports |
| Show security knowledge | MITRE ATT&CK references, SPF/DKIM awareness, threat labelling |

---

## 2. What We Built — Development Journey

PhishGuard was built across four distinct phases in a single session.

### Phase 1 — Core CLI Tool

The foundation: a command-line tool that could parse an email and report on it.

**Files created:**
- `phishguard.py` — main entry point with argument parsing and colored report rendering
- `analyzers/header_analyzer.py` — 8 header-level phishing checks
- `analyzers/url_analyzer.py` — 9 URL-level checks including extraction from HTML anchor tags
- `analyzers/body_analyzer.py` — 7 pattern categories across 50+ regex phrases
- `utils/scorer.py` — weighted scoring and verdict logic
- `samples/phishing1.eml` — simulated PayPal credential spoof
- `samples/phishing2.eml` — simulated IT helpdesk spear-phish
- `samples/legitimate.eml` — genuine-style GitHub notification
- `requirements.txt` — dependency list
- `README.md` — professional project README

**Key decisions made here:**
- Use Python's built-in `email` library (no external parser needed)
- Keep each analyzer in its own module so they are independently testable
- Return findings as plain dicts `{category, severity, detail}` — a simple contract
  that every consumer (terminal, GUI, PDF) can read without any conversion

**Test results from Phase 1:**
- `phishing1.eml` → 100/100 CRITICAL (25 findings)
- `phishing2.eml` → 100/100 CRITICAL (21 findings)
- `legitimate.eml` → 0/100 LOW (0 false positives)

---

### Phase 2 — GUI

A graphical interface was added so the tool could be used without touching a terminal.

**File created:** `gui.py`

**Technology chosen:** CustomTkinter (over plain Tkinter) for its modern flat design,
dark/light mode support, and rounded widget styling — better suited to a portfolio project.

**GUI features built:**
- Sidebar with Load File, Analyze, Clear, and Appearance toggle controls
- Email input text box with placeholder text that clears on focus
- File browser dialog (supports `.eml` and `.txt`)
- Background thread for analysis so the UI never freezes
- Scrollable results panel with:
  - Score card showing the numeric score and risk level in risk-appropriate colors
  - Score progress bar (color matches risk level)
  - Per-category findings with colored severity pills
  - Green "No issues" rows for clean categories
  - Verdict card with colored border
- Status bar at the bottom showing current state

---

### Phase 3 — Threat Classification + PDF Export

Two major features were added to make PhishGuard look and behave like a professional tool.

**Files created:**
- `utils/classifier.py` — MITRE ATT&CK-aligned threat labelling engine
- `utils/pdf_exporter.py` — ReportLab-based PDF report generator

**Files updated:**
- `phishguard.py` — added `--export` CLI flag and classification display section
- `gui.py` — added Export PDF button, threat classification section in results panel
- `requirements.txt` — added `reportlab>=4.0.0`

**Threat classifier approach:**
Each of 6 attack categories has a list of `(regex_pattern, weight)` signal pairs.
The classifier searches the combined email body + subject + From header against all
signals for all categories, sums the weights, and reports any category that exceeds
a minimum threshold. This gives a confidence level (HIGH / MEDIUM / LOW) based on
score magnitude, a rationale string, and a MITRE ATT&CK technique reference.

**PDF exporter approach:**
ReportLab's Platypus (document layout engine) was used rather than raw canvas drawing
because Platypus handles text reflow, page breaks, and table layout automatically.
The PDF includes: branded header block, scan metadata table, score card with progress
bar, threat classification cards, per-category findings tables, verdict, and disclaimer.

---

## 3. Project Structure

```
PhishGuard/
│
├── phishguard.py               # CLI entry point — argument parsing, report rendering
├── gui.py                      # GUI entry point — CustomTkinter application
│
├── analyzers/                  # One module per analysis domain
│   ├── __init__.py
│   ├── header_analyzer.py      # Parses email headers for spoofing / auth failures
│   ├── url_analyzer.py         # Extracts and inspects every URL in the body
│   └── body_analyzer.py        # Scans body text for phishing language patterns
│
├── utils/                      # Shared support utilities
│   ├── __init__.py
│   ├── scorer.py               # Converts findings list → risk score + verdict
│   ├── classifier.py           # Maps findings + body text → threat category labels
│   └── pdf_exporter.py         # Generates a PDF report using ReportLab
│
├── samples/                    # Test emails
│   ├── phishing1.eml           # PayPal credential phish (CRITICAL)
│   ├── phishing2.eml           # IT helpdesk spear-phish (CRITICAL)
│   └── legitimate.eml          # GitHub notification (LOW, 0 false positives)
│
├── requirements.txt            # pip dependencies
├── README.md                   # Public-facing project README
└── DOCUMENTATION.md            # This file
```

---

## 4. Architecture & Data Flow

```
Input (file or paste)
        │
        ▼
 email.message_from_*()          ← Python standard library email parser
        │
        ├──────────────────────────────────────────────┐
        │                                              │
        ▼                                              ▼
 analyze_headers(msg)          get_body_text(msg)  ──► analyze_urls(body)
 [header_analyzer.py]          [body_analyzer.py]      [url_analyzer.py]
        │                              │                       │
        │                              ▼                       │
        │                      analyze_body(msg)               │
        │                      [body_analyzer.py]              │
        │                              │                       │
        └──────────────────────────────┴───────────────────────┘
                                       │
                               all_findings: list[dict]
                            {category, severity, detail}
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                   │
                    ▼                  ▼                   ▼
            calculate_score()  get_risk_level()   classify_threat()
            [scorer.py]        [scorer.py]        [classifier.py]
                    │                  │                   │
                    └──────────────────┴───────────────────┘
                                       │
                            ┌──────────┴──────────┐
                            │                     │
                            ▼                     ▼
                    Terminal Report           export_pdf()
                    [phishguard.py]         [pdf_exporter.py]
                         or
                    GUI Results Panel
                    [gui.py]
```

**The finding dict contract** — every analyzer returns a list of these:

```python
{
    "category":  str,   # "Header" | "URL" | "Body"
    "severity":  str,   # "HIGH" | "MEDIUM" | "LOW"
    "detail":    str,   # Human-readable description of the specific issue found
}
```

This uniform shape means the scorer, classifier, GUI renderer, and PDF exporter all
consume the same data without any transformation layer.

---

## 5. Component Deep-Dives

### 5.1 Header Analyzer

**File:** `analyzers/header_analyzer.py`

**Input:** A parsed `email.message.Message` object

**What it does:**

The header analyzer reads raw email headers and applies 8 checks. Headers are where
the first and most reliable phishing signals live because attackers must set certain
headers to route the email, and those headers often contradict each other.

| Check | What It Detects | Severity |
|-------|----------------|----------|
| From / Reply-To mismatch | Reply-To set to a different address so replies go to attacker | HIGH |
| Return-Path domain mismatch | Envelope sender domain differs from displayed From domain | MEDIUM |
| Display name brand impersonation | "PayPal Security" in display name but domain is evil.xyz | HIGH |
| Suspicious sending domain | Domain is a known disposable/throwaway mail provider | HIGH |
| SPF fail / softfail | Authentication-Results or Received-SPF header shows failure | HIGH / MEDIUM |
| SPF none | No SPF record exists for the sending domain | MEDIUM |
| DKIM failure | DKIM signature did not verify | HIGH |
| No DKIM signature | Email has no DKIM-Signature header at all | LOW |
| Bulk mailer X-Mailer | PHPMailer, SendBlaster, etc. in X-Mailer header | MEDIUM |
| X-Originating-IP present | Exposes attacker's sending server IP | LOW |

**Key helper functions:**
- `_extract_address(header)` — pulls `addr@domain.com` out of `"Display Name <addr@domain.com>"`
- `_extract_display_name(header)` — pulls `Display Name` out of the same string
- `_get_domain(email_address)` — returns just the domain portion

**SPF / DKIM detection approach:**

Rather than parsing authentication headers with a dedicated library, the analyzer
searches the raw string values of `Received-SPF` and `Authentication-Results` for
substrings like `spf=fail`, `spf=softfail`, `spf=none`, and `dkim=fail`. This is
intentionally simple and works against real email headers because these values are
standardized in RFC 7208 and RFC 6376.

---

### 5.2 URL Analyzer

**File:** `analyzers/url_analyzer.py`

**Input:** Raw email body string (HTML or plain text)

**What it does:**

URLs are the primary attack vector in phishing emails. The URL analyzer first
extracts every URL from the body (including those hidden behind anchor tag display
text), then inspects each one independently.

**Extraction — two-pass approach:**

1. **Anchor tag pass:** A regex scans for `<a href="URL">display text</a>` patterns.
   Both the real URL and the visible display text are captured as a pair. This is
   critical because `<a href="evil.com">paypal.com</a>` looks legitimate in an
   email client but is a classic deception.

2. **Plain text pass:** A second regex catches any remaining `http://` or `https://`
   URLs that appear as raw text (not inside an anchor tag).

**Per-URL checks:**

| Check | What It Detects | Severity |
|-------|----------------|----------|
| IP-based host | `http://192.168.1.1/login` — no domain name | HIGH |
| Suspicious TLD | `.xyz`, `.tk`, `.ml`, `.ru`, `.cn`, and 20+ others | MEDIUM |
| URL shortener | bit.ly, tinyurl.com, t.co, and 15+ others | MEDIUM |
| Excessive subdomains | 3+ subdomain levels (e.g. `a.b.c.evil.com`) | MEDIUM |
| Brand in subdomain | `paypal.evil.com` — brand is subdomain, not real domain | HIGH |
| Misleading anchor text | Display text is a URL that differs from the real href | HIGH |
| URL-encoded characters | `%XX` encoding that may obfuscate the real destination | LOW |
| Suspicious path keywords | `/login`, `/verify`, `/account` on unknown domains | LOW |
| HTTP on sensitive pages | Unencrypted connection for login/account/bank pages | MEDIUM |

**Brand subdomain detection logic:**

```
hostname = "paypal.account-secure.verify.xyz"
parts    = ["paypal", "account-secure", "verify", "xyz"]
subdomains = "paypal.account-secure.verify"   ← everything except last 2 parts
base_domain = "verify"

If "paypal" is in subdomains AND "paypal" is NOT in base_domain → flag it
```

---

### 5.3 Body Analyzer

**File:** `analyzers/body_analyzer.py`

**Input:** A parsed `email.message.Message` object (decodes multipart automatically)

**What it does:**

The body analyzer scans the email's text content for social engineering language.
It works entirely with regex pattern lists, which makes the detection rules easy
to read, extend, and audit.

**Five pattern categories:**

| Category | Example Phrases | Severity |
|----------|----------------|----------|
| Urgency / pressure | "act now", "your account will be suspended", "last warning", "failure to respond" | HIGH |
| Credential requests | "enter your password", "social security number", "confirm your identity" | HIGH |
| Action prompts | "click here", "open the attachment", "enable macros", "scan the QR code" | MEDIUM |
| Social engineering lures | "you have won", "unusual activity detected", "unclaimed package" | MEDIUM |
| Impersonation language | "dear valued customer", "your PayPal account", "IT department" | LOW |

**Multipart handling:**

The `_extract_plain_text()` function walks the MIME tree and collects both
`text/plain` and `text/html` parts. This ensures the analyzer catches phishing
phrases whether the email is plain text, HTML-only, or a multipart mix.

**Additional structural checks:**
- **JavaScript in body** (`<script>` tag) — rated HIGH because legitimate emails
  never need JavaScript
- **Long base64 blocks** — 100+ character base64 strings in body text may indicate
  hidden payload or content obfuscation

---

### 5.4 Scoring Engine

**File:** `utils/scorer.py`

**Input:** The combined `all_findings` list from all three analyzers

**What it does:**

Converts a heterogeneous list of findings into a single 0–100 integer score.

**Severity weights:**

| Severity | Points per Finding |
|----------|--------------------|
| HIGH     | 18                 |
| MEDIUM   | 10                 |
| LOW      | 4                  |

**Design rationale:**
- A single HIGH finding scores 18 — not enough to alarm by itself
- Three HIGH findings score 54 — crosses into the HIGH risk band
- Five HIGH findings score 90 — approaches CRITICAL
- The score is capped at 100

**Risk level thresholds:**

| Score Range | Level    |
|-------------|----------|
| 75 – 100    | CRITICAL |
| 50 – 74     | HIGH     |
| 25 – 49     | MEDIUM   |
| 0  – 24     | LOW      |

**Verdict strings** are generated by `get_verdict(score)` — a plain-English sentence
matched to the score band, used in both the terminal report and PDF.

---

### 5.5 Threat Classifier

**File:** `utils/classifier.py`

**Input:** `findings` list, `body_text` string, `msg` object (for subject/from headers)

**What it does:**

Assigns one or more threat category labels to the email, each with a confidence
level, rationale, and MITRE ATT&CK technique reference.

**Six attack categories:**

| Label | MITRE Reference | Key Signals |
|-------|----------------|-------------|
| Credential Harvesting | T1598 | password/login/verify/SSN/credit card requests |
| Business Email Compromise | T1534 / T1566.002 | wire transfer, invoice, IT helpdesk, payroll |
| Delivery / Logistics Scam | T1566 | package, FedEx, UPS, tracking number, customs fee |
| Account Takeover Attempt | T1078 | account suspended, unauthorized access, security alert |
| Malware Delivery | T1566.001 | open attachment, enable macros, .exe/.zip/.docm |
| Financial Fraud | T1657 | lottery won, unclaimed prize, inheritance, tax refund |

**Classification algorithm:**

```python
for each category:
    score = 0
    for each (regex_pattern, weight) in category_signals:
        if pattern matches in (body + subject + from):
            score += weight

    if score >= THRESHOLD (3):
        confidence = HIGH if score >= 8, MEDIUM if >= 4, else LOW
        add to results
```

Results are sorted by score descending so the most likely threat appears first.
If no category meets the threshold but findings exist, a fallback
`Generic Spam / Phishing` label is returned.

---

### 5.6 PDF Exporter

**File:** `utils/pdf_exporter.py`

**Technology:** ReportLab (Platypus document layout engine)

**Why ReportLab over alternatives:**
- Ships as a single pip package with no system dependencies
- Platypus handles text reflow and page breaks automatically
- Full control over visual styling, colors, and table layout
- Widely used in professional Python tooling

**PDF structure (top to bottom):**

1. **Branded header table** — dark background, PhishGuard logo, subtitle
2. **Scan metadata table** — date/time, source filename, subject, from address
3. **Score card** — large numeric score, risk level badge, verdict text in one row
4. **Score progress bar** — visual bar filled proportionally, colored by risk level
5. **Threat classification cards** — one card per detected threat, with confidence,
   rationale, and MITRE ATT&CK reference
6. **Finding summary table** — total / HIGH / MEDIUM / LOW counts
7. **Per-category findings tables** — Header, URL, Body sections with colored
   sub-headers and alternating row backgrounds
8. **Footer** — disclaimer and generation timestamp

**Color system in the PDF:**
All risk/severity colors match the GUI palette exactly so a user comparing the GUI
and the PDF sees consistent visual language.

---

### 5.7 CLI Entry Point

**File:** `phishguard.py`

**Two input modes:**

| Mode | How It Works |
|------|-------------|
| File mode | `python phishguard.py email.eml` — reads file as bytes, parses with `email.message_from_bytes()` |
| Paste mode | No argument — prompts user to paste, terminated by typing `END` on its own line |

**CLI flags:**

| Flag | Effect |
|------|--------|
| *(no flag)* | Terminal report only |
| `--export` | Auto-generates a timestamped PDF in the same folder as the input file |
| `--export report.pdf` | Saves PDF to the specified path |
| `--show-body` | Prints the raw extracted body before the report (debug aid) |

**Report rendering:**

The terminal report is built with `colorama` for cross-platform ANSI color support.
Each section (`_print_banner`, `_print_score_block`, `_print_classifications`,
`_print_section`, `_print_verdict`) is a standalone function so the report layout
can be modified without touching analysis logic.

Text wrapping uses Python's `textwrap.wrap()` to keep long finding details within
the banner width, ensuring the report looks clean at any terminal size.

---

### 5.8 GUI

**File:** `gui.py`

**Technology:** CustomTkinter 5.x

**Layout:**

```
┌─────────────────┬─────────────────────────────────────────────┐
│                 │  EMAIL INPUT                [filename]       │
│  🛡 PhishGuard  │  ┌─────────────────────────────────────────┐ │
│                 │  │ (text box — paste or loaded file)       │ │
│  Load File      │  └─────────────────────────────────────────┘ │
│  Analyze Email  │                                               │
│  Export PDF     │  ANALYSIS RESULTS          [score badge]     │
│  Clear          │  ┌─────────────────────────────────────────┐ │
│                 │  │ Score card + progress bar               │ │
│  Appearance ▾   │  │ Threat classification cards             │ │
│                 │  │ Header findings                         │ │
│  v1.0           │  │ URL findings                            │ │
│                 │  │ Body findings                           │ │
└─────────────────│  │ Verdict card                            │ │
                  │  └─────────────────────────────────────────┘ │
                  │  [status bar]                                 │
                  └───────────────────────────────────────────────┘
```

**Threading model:**

Analysis runs in a `daemon=True` background thread so the UI never freezes. When
the thread finishes, it calls `self.after(0, callback)` to safely schedule the
UI update back on the main tkinter thread. This is the correct pattern for tkinter
— all widget updates must happen on the main thread.

**PDF export flow in GUI:**

1. User clicks Export PDF → `filedialog.asksaveasfilename()` opens a save dialog
2. Chosen path is handed to a second background thread
3. `export_pdf()` runs in the thread
4. On completion, `self.after(0, ...)` triggers a success messagebox on main thread

**State management:**

`self._last_results` stores the full analysis output dict after each run. The
Export PDF button remains disabled until a successful analysis populates this dict,
preventing exports with no data.

---

## 6. Detection Coverage Reference

### Header Checks (8 checks)

| # | Check | Logic | Severity |
|---|-------|-------|----------|
| H1 | From / Reply-To mismatch | `reply_to_addr != from_addr` | HIGH |
| H2 | Return-Path domain mismatch | `return_path_domain != from_domain` | MEDIUM |
| H3 | Display name brand impersonation | Brand keyword in display name but not in domain | HIGH |
| H4 | Suspicious sending domain | Domain in hardcoded blocklist | HIGH |
| H5 | SPF fail / softfail | `spf=fail` or `spf=softfail` in auth headers | HIGH |
| H6 | SPF none | `spf=none` in auth headers | MEDIUM |
| H7 | DKIM failure | `dkim=fail` in Authentication-Results | HIGH |
| H8 | No DKIM signature | No DKIM-Signature header present | LOW |
| H9 | Bulk mailer X-Mailer | PHPMailer / SendBlaster in X-Mailer | MEDIUM |
| H10 | X-Originating-IP present | Header exists | LOW |

### URL Checks (9 checks)

| # | Check | Logic | Severity |
|---|-------|-------|----------|
| U1 | IP-based host | Hostname matches IPv4 regex | HIGH |
| U2 | Suspicious TLD | TLD in blocklist of 30+ abused TLDs | MEDIUM |
| U3 | URL shortener | Hostname in shortener list | MEDIUM |
| U4 | Excessive subdomains | Subdomain count >= 3 | MEDIUM |
| U5 | Brand in subdomain | Brand in subdomain parts, not base domain | HIGH |
| U6 | Misleading anchor text | Display host differs from actual href host | HIGH |
| U7 | URL-encoded characters | `%` present and decoded URL differs | LOW |
| U8 | Suspicious path keywords | login/verify/account/secure on unknown domain | LOW |
| U9 | HTTP on sensitive page | Scheme is http and URL contains login/bank keywords | MEDIUM |

### Body Checks (7 pattern categories)

| # | Category | Pattern Count | Severity |
|---|----------|--------------|----------|
| B1 | Urgency / pressure phrases | 13 patterns | HIGH |
| B2 | Credential harvesting phrases | 9 patterns | HIGH |
| B3 | Suspicious action prompts | 7 patterns | MEDIUM |
| B4 | Social engineering lures | 10 patterns | MEDIUM |
| B5 | Impersonation language | 5 patterns | LOW |
| B6 | JavaScript in email body | `<script>` tag present | HIGH |
| B7 | Base64 obfuscation | 100+ char base64 string in body | LOW |

---

## 7. Threat Classification Reference

### How Confidence Is Determined

Signal scores are the sum of matched pattern weights within a category.

| Raw Score | Confidence |
|-----------|-----------|
| 8+        | HIGH       |
| 4–7       | MEDIUM     |
| 3         | LOW        |
| < 3       | Not reported |

### Classification Cards

**Credential Harvesting** · MITRE T1598
- Triggered by: password/login requests, verify account, SSN, credit card details
- Typically combined with: fake login page URLs, urgency pressure, impersonation

**Business Email Compromise (BEC)** · MITRE T1534 / T1566.002
- Triggered by: wire transfer, invoice, IT helpdesk impersonation, payroll references
- Often has no malicious URLs — relies purely on social engineering to authority

**Delivery / Logistics Scam** · MITRE T1566
- Triggered by: FedEx/UPS/DHL names, "package on hold", customs fee, tracking number
- Lures victim to fake carrier login page or payment portal

**Account Takeover Attempt** · MITRE T1078
- Triggered by: "account suspended", unauthorized access, security alert, reset password
- Creates urgency around losing account access to drive credential submission

**Malware Delivery** · MITRE T1566.001
- Triggered by: "open the attachment", "enable macros", file extension keywords
- The email is a delivery vehicle for a malicious payload

**Financial Fraud** · MITRE T1657
- Triggered by: lottery, inheritance, unclaimed prize, tax refund, advance fee
- Classic 419 / advance-fee fraud patterns

---

## 8. Scoring System Explained

### Why Weighted Severity?

Not all phishing signals are equally damning. A missing DKIM signature (LOW) alone
is not meaningful — many small organisations don't configure DKIM. But a combination
of SPF failure + Reply-To mismatch + credential request phrases is a very strong
indicator even before counting URL issues.

The weighted system means:
- A single LOW finding gives a score of 4 → stays in LOW band (as expected)
- A single HIGH finding gives 18 → still LOW band (a single flag isn't conclusive)
- 3× HIGH findings give 54 → HIGH band
- 5× HIGH + 2× MEDIUM findings give 110, capped to 100 → CRITICAL

### Tuning the Weights

The weights in `utils/scorer.py` can be adjusted without touching any other file:

```python
SEVERITY_WEIGHTS = {
    "HIGH":   18,
    "MEDIUM": 10,
    "LOW":     4,
}
```

To make the tool more sensitive, lower the thresholds in `RISK_LEVELS` or increase
weights. To reduce false positives, raise the thresholds.

---

## 9. Usage Guide

### Installation

```bash
# 1. Navigate to the project folder
cd "C:\Users\USER01\Desktop\MY CYBERSEC PROJECTS\PhishGuard"

# 2. Install dependencies
pip install -r requirements.txt
```

### Launch the GUI

```bash
python gui.py
```

### CLI — Analyze a file

```bash
python phishguard.py samples/phishing1.eml
python phishguard.py samples/phishing2.eml
python phishguard.py samples/legitimate.eml
```

### CLI — Interactive paste mode

```bash
python phishguard.py
# Paste your email content, then type END and press Enter
```

### CLI — Export PDF

```bash
# Auto-named PDF saved next to the input file
python phishguard.py samples/phishing1.eml --export

# Specific output path
python phishguard.py samples/phishing1.eml --export my_report.pdf
```

### Getting Raw Email Text from Real Email Clients

| Client | Steps |
|--------|-------|
| Gmail | Open email → ⋮ (three dots) → Show original → Copy all |
| Outlook | Open email → File → Properties → Internet headers (copy), then copy body separately |
| Thunderbird | Open email → View → Message Source (Ctrl+U) |
| Apple Mail | Open email → View → Message → Raw Source |

### VS Code Launch

Open the project folder in VS Code, then either:
- Press **Ctrl+`** to open the terminal and run `python gui.py`
- Press **F5** with `gui.py` open to launch with the debugger
- Use the `.vscode/launch.json` config for named run configurations

---

## 10. Sample Outputs

### phishing1.eml (PayPal credential spoof)

```
Risk Score : 100/100
Risk Level : CRITICAL

Threat Classification:
  [>>] Credential Harvesting       [HIGH confidence]
  [>>] Account Takeover Attempt    [LOW confidence]

Header: 5 findings (4× HIGH, 1× MEDIUM)
  - From/Reply-To mismatch
  - Display name impersonates "paypal"
  - SPF check failed
  - DKIM signature failed
  - PHPMailer X-Mailer detected

URL: 4 findings (2× HIGH, 2× MEDIUM)
  - Misleading anchor text (paypal.com displayed, evil.xyz actual)
  - Brand "paypal" used as subdomain
  - Suspicious TLD .xyz
  - Unencrypted HTTP on login page

Body: 16 findings (12× HIGH, 1× MEDIUM, 3× LOW)
  - 6 urgency phrases
  - 6 credential request phrases
  - 1 action prompt
  - 3 impersonation phrases
```

### phishing2.eml (IT helpdesk spear-phish)

```
Risk Score : 100/100
Risk Level : CRITICAL

Threat Classification:
  [>>] Business Email Compromise   [HIGH confidence]
  [>>] Account Takeover Attempt    [HIGH confidence]
  [>>] Credential Harvesting       [LOW confidence]

Header: 6 findings
  - From/Reply-To mismatch (Reply-To to mailinator.com)
  - Return-Path domain mismatch (mass-emailer.ru)
  - SPF softfail
  - No DKIM signature
  - SendBlaster X-Mailer
  - X-Originating-IP exposed

URL: 4 findings
  - IP-based URL (192.168.10.55)
  - Unencrypted HTTP on login page
  - URL shortener (bit.ly)
  - Suspicious login keyword in path

Body: 11 findings
  - 6 urgency phrases
  - 1 credential request
  - 2 action prompts
  - 2 impersonation phrases
```

### legitimate.eml (GitHub notification)

```
Risk Score : 0/100
Risk Level : LOW

Threat Classification: No dominant threat pattern identified.

Header:  ✓ No issues detected
URL:     ✓ No issues detected
Body:    ✓ No issues detected

Verdict: This email appears relatively low-risk.
```

---

## 11. Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `colorama` | >=0.4.6 | ANSI terminal colors on Windows |
| `customtkinter` | >=5.2.0 | Modern GUI widgets (dark/light themed) |
| `reportlab` | >=4.0.0 | PDF generation via Platypus layout engine |

**Standard library modules used (no install needed):**

| Module | Used For |
|--------|---------|
| `email` | Parsing `.eml` files and multipart MIME bodies |
| `re` | All regex pattern matching |
| `urllib.parse` | URL parsing (`urlparse`, `unquote`) |
| `argparse` | CLI argument parsing |
| `textwrap` | Word-wrapping long lines in terminal output |
| `threading` | Background analysis thread in GUI |
| `tkinter` | Base GUI layer under CustomTkinter |
| `datetime` | Timestamps in PDF report |
| `os` | File path operations |

---

## 12. Design Decisions & Trade-offs

### Offline-only / No API calls

**Decision:** All analysis is done with local logic — no VirusTotal, no WHOIS lookups,
no DNS queries, no threat intelligence feeds.

**Why:** Keeps the tool portable (works on any machine with Python), fast (no network
latency), private (no email content leaves the machine), and dependency-free from a
network perspective. The trade-off is that URL reputation and domain age data are not
available.

### findings as plain dicts (not dataclasses)

**Decision:** Findings are `dict` objects rather than typed dataclasses or namedtuples.

**Why:** Simplicity. Every consumer just reads `f["severity"]` and `f["detail"]`.
Adding a dataclass would require an import in every analyzer module with no practical
benefit at this scale. If the project grew to hundreds of finding types, switching to
dataclasses would make sense.

### Regex-based detection (not ML)

**Decision:** All detection uses hand-written regex patterns rather than a trained model.

**Why:** Transparent, auditable, and explainable — you can read exactly what triggers a
finding. A machine learning model would be a black box and would require a training dataset,
which is impractical for an offline tool. The trade-off is that novel phrasing not covered
by the patterns may be missed.

### CustomTkinter over PyQt / wxPython

**Decision:** CustomTkinter was chosen for the GUI.

**Why:** It is a thin wrapper over standard tkinter (always available with Python), installs
as a single package, provides a visually modern appearance out of the box, and does not
require any C compiler or system libraries. PyQt5/6 would give more power but adds complexity
and licensing considerations.

### ReportLab over fpdf2 / WeasyPrint

**Decision:** ReportLab's Platypus was used for PDF generation.

**Why:** Platypus handles automatic text reflow and multi-page layout, which is essential
for reports where the number of findings is variable. fpdf2 is simpler but requires manual
line-break management. WeasyPrint renders HTML to PDF which would add an HTML template
layer and a system dependency (Pango/Cairo on Windows).

---

## 13. Known Limitations

| Limitation | Impact | Potential Fix |
|------------|--------|--------------|
| Static analysis only — URLs are not visited | Cannot detect malicious pages with benign-looking URLs | Integrate VirusTotal API (optional, online mode) |
| No attachment scanning | Malware in attachments is not detected | Add file extraction and basic YARA scanning |
| HTML rendering not simulated | Hidden text (white text on white background) is not detected | Parse and analyze computed visual text |
| English-only pattern lists | Non-English phishing emails score low | Add multilingual pattern sets |
| IP in URL check uses simple regex | Does not handle IPv6 URLs | Extend IP regex |
| No domain age / WHOIS check | Newly registered domains are not flagged | Add optional WHOIS lookup |
| Regex can be evaded by unusual spacing | `v e r i f y   y o u r` is not matched | Add text normalization before matching |

---

## 14. Potential Future Enhancements

1. **VirusTotal URL lookup** — optional `--online` flag that checks extracted URLs against the
   VirusTotal API for reputation data

2. **Attachment analysis** — extract and inspect attachments; flag suspicious file types
   (`.exe`, `.js`, `.docm`), check for embedded macros

3. **WHOIS domain age** — newly registered domains (< 30 days) are a strong phishing indicator

4. **Bulk analysis mode** — `--bulk /path/to/folder/` to scan an entire directory of `.eml` files
   and produce a summary CSV

5. **Email client plugins** — package as an Outlook add-in or Thunderbird extension for
   one-click in-client analysis

6. **Multilingual support** — add pattern lists for common phishing languages (Spanish,
   French, German, Portuguese)

7. **YARA rule integration** — run YARA rules against email body and attachments for
   known malware family signatures

8. **Whitelist / trust list** — allow users to mark known-good domains so internal company
   emails don't generate false positives

9. **Dark web email breach check** — optional integration with HaveIBeenPwned API to check
   if the recipient address appears in known breach data

10. **Machine learning layer** — train a classifier on a labeled phishing dataset to complement
    the rule-based engine

---

## 15. Disclaimer

PhishGuard was built for **educational and portfolio purposes** — to demonstrate practical
Python application development in a cybersecurity context. It covers:

- Secure email analysis concepts (SPF, DKIM, header inspection)
- Regex-based threat detection
- MITRE ATT&CK framework awareness
- Python module architecture (separation of concerns)
- GUI development with CustomTkinter
- PDF report generation with ReportLab
- CLI design with argparse

**This tool is not a production security control.** It should not be used as a sole
mechanism for deciding whether an email is safe. It is intended for:
- Cybersecurity coursework and learning
- CTF (Capture the Flag) challenges
- Security awareness training demonstrations
- Portfolio demonstration of Python + security skills

Always use authorized email samples only. Never analyze emails you do not have permission
to inspect.

---

*PhishGuard v1.0 — Built with Python 3.10+ | colorama | customtkinter | reportlab*
