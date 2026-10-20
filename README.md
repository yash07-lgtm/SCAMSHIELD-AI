# ScamShield AI — Email Spam & Scam Message Detector

A local-only cybersecurity web application that analyses pasted email, SMS, and chat messages for spam and scam indicators using rule-based pattern matching.

Built with **Python 3.8+**, **Flask**, **Bootstrap 5**, and custom CSS.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Project Structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Running the Application](#running-the-application)
6. [Using the Application](#using-the-application)
7. [Running the Tests](#running-the-tests)
8. [Detection Logic](#detection-logic)
9. [Limitations](#limitations)
10. [Privacy and Security](#privacy-and-security)
11. [Screenshots Guidance](#screenshots-guidance)
12. [Project Status](#project-status)

---

## Architecture

```
Browser  ──POST /analyze──►  Flask (app.py)
                                  │
                         detector/engine.py
                                  │
                         detector/rules.py
                         (12 rule categories)
                                  │
                          JSON response
                         (verdict, score,
                          warnings, recs)
                                  │
Browser ◄── render via JS textContent (XSS-safe)
```

All processing is local. No message text leaves the machine.

---

## Project Structure

```
ScamShield-AI/
├── app.py                      # Flask entry point — GET / and POST /analyze
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── detector/
│   ├── __init__.py
│   ├── engine.py               # Scoring, verdict mapping, explanation builder
│   └── rules.py                # 12 rule-category functions
│
├── templates/
│   └── index.html              # Single-page UI (Bootstrap 5 + inline JS)
│
├── static/
│   └── css/
│       └── style.css           # Dark navy + cyan theme
│
└── tests/
    ├── test_engine.py          # Engine, rule, and route unit tests (34 tests)
    ├── test_phase3_ui.py       # UI regression and API shape tests (28 tests)
    └── test_security_review.py # Security and quality review tests (45 tests)
```

---

## Requirements

- **Python 3.8 or newer** (tested on 3.12 / 3.15)
- Internet connection for the first browser load (Bootstrap 5 and Bootstrap Icons load from CDN)

---

## Installation

### 1. Get the code

```powershell
# Clone (or download and extract the ZIP):
cd ScamShield-AI
```

### 2. Create a virtual environment

```powershell
# Windows — use the py launcher if 'python' is not in PATH:
py -m venv venv

# macOS / Linux:
python3 -m venv venv
```

### 3. Activate the virtual environment

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
source venv/bin/activate
```

### 4. Install dependencies

```powershell
pip install -r requirements.txt
```

> `scikit-learn`, `pandas`, and `joblib` are listed for future Phase 4 (ML classifier) work.
> The running application only requires `flask`.

---

## Running the Application

```powershell
flask --app app run --debug
```

Open your browser at **http://127.0.0.1:5000**

> The `--debug` flag enables automatic reloading when files change.
> **Do not use `--debug` or expose this server to the internet.**
> This is a local development server only.

---

## Using the Application

1. **Paste** any email, SMS, or chat message into the text area, or click one of the **six sample buttons** to load a pre-written example:
   - **Phishing** — Netflix account suspension phishing email
   - **Prize Spam** — Fake gift card prize claim
   - **OTP Scam** — Fake bank OTP harvesting SMS
   - **Payment Fraud** — Fake overdue invoice with threats
   - **Legitimate** — Routine dental appointment reminder
   - **Appointment** — Amazon order shipping notification

2. Click **Analyze Message**.

3. The results panel shows:
   - **Classification** — Potentially Legitimate / Suspicious / Spam or Scam
   - **Risk level bar** — colour-keyed Low (green) / Medium (amber) / High (red)
   - **Risk score** (0–100), **Confidence** (Low/Medium/High), **Signal count**
   - **What We Found** — plain-language explanation with disclaimer
   - **Warning Signs Detected** — each with rule name, description, and the exact excerpt that triggered it
   - **Recommended Actions** — context-specific next steps

4. Click **Clear** to reset.

---

## Running the Tests

```powershell
# Run all 107 tests:
python -m unittest discover -s tests -v

# Run a specific file:
python -m unittest tests.test_engine -v
python -m unittest tests.test_phase3_ui -v
python -m unittest tests.test_security_review -v
```

Expected output:
```
Ran 107 tests in ~1.7s
OK
```

### Test coverage summary

| File | Tests | What it covers |
|---|---|---|
| `test_engine.py` | 34 | Rule functions, scoring, verdict mapping, Flask routes |
| `test_phase3_ui.py` | 28 | API shape, 6 sample messages, verdict metadata, output safety, template structure |
| `test_security_review.py` | 45 | Form validation, classifications, warnings, HTML injection, edge inputs, no storage/transmission, no spurious accuracy claims |

---

## Detection Logic

The engine uses **pattern-matching rules only** — no trained model, no external API.

### Verdict thresholds

| Score | Verdict |
|---|---|
| 0 – 29 | Potentially Legitimate |
| 30 – 59 | Suspicious / Possible Scam |
| 60 + | Spam / Scam |

### Rule categories

| Rule | Signals | Weight |
|---|---|---|
| Urgency / Pressure | "act now", "expires in 24 hours", "deadline" … | 15 |
| Threat / Fear Tactic | "account will be suspended", "legal action", "arrest" … | 20 |
| Credential / Personal Info Request | "password", "OTP", "PIN", "verify your payment" … | 25 |
| Prize / Lottery Claim | "you've won", "congratulations", "gift card" … | 20 |
| Unexpected Payment Demand | "wire transfer", "bitcoin", "unpaid invoice" … | 20 |
| Possible Brand Impersonation | Netflix, PayPal, Amazon, IRS, HMRC … | 8 |
| URL Shortener Detected | bit.ly, tinyurl, t.co, ow.ly … | 18 |
| IP Address URL | http://x.x.x.x/… | 22 |
| Suspicious Domain Extension | .xyz, .top, .click, .loan … | 20 |
| Brand Lookalike Domain | paypal-secure.com, netflix-update.xyz … | 25 |
| Excessive Capital Letters | >40 % uppercase letters | 8 |
| Excessive Punctuation | !!!, ??? | 5 |

The score is capped at 100. The confidence label reflects both score and number of signals triggered.

---

## Limitations

- **Rule-based only.** The detector uses hand-crafted patterns. It will miss novel scam techniques that do not match any known pattern, and may occasionally flag legitimate messages (false positives) if they share vocabulary with scam messages (e.g. a legitimate security newsletter).

- **No trained classifier.** A machine-learning Phase 4 was planned but not implemented. All results are from pattern matching, not statistical learning.

- **English only.** Rules are written for English text. Non-English messages will receive very low scores regardless of content.

- **No URL visiting.** Suspicious URLs are detected by pattern only (domain structure, TLD, shorteners). The engine never fetches or resolves any URL.

- **Score is additive.** Multiple triggers of the same rule category (e.g. three urgent phrases) each add weight, which can inflate scores for messages with repetitive language.

- **Not a security guarantee.** Results are an automated heuristic assessment. Always verify suspicious messages through official channels before taking any action.

---

## Privacy and Security

| Property | Detail |
|---|---|
| **Local only** | Flask runs on `127.0.0.1`. Nothing is exposed to the network. |
| **No storage** | Messages are discarded after the HTTP response. No file writes, no database. |
| **No external calls** | `detector/rules.py` and `detector/engine.py` import only Python standard library (`re`). No network requests are made. |
| **XSS protection** | All user-supplied text is rendered via JavaScript `textContent`, never `innerHTML`. Jinja2 autoescape is active for all HTML templates. |
| **Input validation** | Empty and whitespace-only messages return HTTP 400. Messages over 20,000 characters are rejected. |
| **No accuracy inflation** | The homepage explicitly states results come from pattern-matching rules, not a trained model. No precision/recall/F1 figures are reported. |

---

## Screenshots Guidance

To document the application for a report or portfolio, capture these views:

1. **Homepage** — full page showing the navbar, hero section, and the How It Works cards.
2. **Analyzer with input** — textarea filled with a sample message and the six sample-load buttons visible.
3. **Scam result** — results panel showing a red "Spam / Scam" verdict, the risk bar at High, and several warning signs with excerpts.
4. **Legitimate result** — results panel showing a green "Potentially Legitimate" verdict, empty warning list, and the three general safety recommendations.
5. **Safety Tips section** — the four cybersecurity tip cards at the bottom of the page.

Use the browser's built-in screenshot tool or a screen-capture utility. Resize to ≥ 1280 px wide for readable captures.

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | Project scaffold, responsive dark-theme UI | ✅ Complete |
| **Phase 2** | Rule-based detection engine, `POST /analyze` API | ✅ Complete |
| **Phase 3** | Enhanced results UI — risk bar, warnings, recommendations | ✅ Complete |
| **Phase 4** | Machine-learning classifier (scikit-learn) | ⏳ Not started |

---

## Running Without a Virtual Environment (not recommended)

If you cannot create a venv, install Flask globally and run directly:

```powershell
pip install flask
flask --app app run
```

This may conflict with other Python projects on the same machine.
