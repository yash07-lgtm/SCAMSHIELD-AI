# ScamShield AI — Implementation Plan

## Top-Level Overview

Build a local-only Flask web application that accepts a pasted email, SMS, or chat message, runs it through a rule-based scoring engine, and returns a verdict (Potentially Legitimate / Suspicious / Scam) together with a list of triggered warning signs and a short excerpt from the message for each one. No data is stored. No external services are contacted. The project lives entirely inside a `scamshield/` subfolder.

The work is divided into four phases:
- **Phase 1** — Project scaffold and Flask skeleton
- **Phase 2** — Rule-based detector and full UI
- **Phase 3** — Machine learning classifier (added after Phase 2 is stable)
- **Phase 4** — Optional polish

Only Phases 1 and 2 are in scope for initial implementation. Phase 3 is documented so it can be picked up later without redesign.

---

## Architecture Summary

- `app.py` — Flask entry point; defines two routes: `GET /` (serve UI) and `POST /analyze` (return JSON verdict)
- `detector/rules.py` — all heuristic rule functions; each rule returns a dict with `rule`, `weight`, and `excerpt`
- `detector/engine.py` — imports rules, scores the message, maps score to verdict, builds the response payload
- `templates/index.html` — Bootstrap 5 single-page UI: textarea + submit button + results card
- `templates/base.html` — shared HTML shell with Bootstrap 5 CDN link and navbar
- `static/css/custom.css` — minimal style overrides
- `static/js/app.js` — fetch POST to `/analyze`, renders verdict badge and warnings list without page reload

The browser never reloads. The JS layer sends the message as JSON and renders the response inline.

---

## Sub-Task 1 — Project Scaffold

**Intent:** Create the folder structure, empty files, and minimal Flask app so the development server starts cleanly. Establishes the foundation every later sub-task builds on.

**Expected Outcomes:**
- `scamshield/` folder exists with all directories and placeholder files in place
- `requirements.txt` lists `flask`
- `flask --app app run --debug` starts without errors and serves a placeholder page at `http://127.0.0.1:5000`

**Todo List:**
1. Create `scamshield/` and all subdirectories: `detector/`, `templates/`, `static/css/`, `static/js/`
2. Create `scamshield/requirements.txt` containing `flask`
3. Create `scamshield/detector/__init__.py` (empty)
4. Create minimal `scamshield/app.py` with a single `GET /` route returning `"ScamShield AI — OK"`
5. Create empty placeholder files: `detector/engine.py`, `detector/rules.py`, `templates/base.html`, `templates/index.html`, `static/css/custom.css`, `static/js/app.js`

**Relevant Context:** None — clean slate.

**Status:** [ ] pending

---

## Sub-Task 2 — Rule-Based Detector Engine

**Intent:** Implement all heuristic rules and the scoring engine so the detector can classify messages and return structured results. This is the core intelligence of the application.

**Expected Outcomes:**
- `detector/rules.py` exports a `run_all_rules(text: str) -> list[dict]` function
- Each returned dict has keys: `rule` (str), `weight` (int), `excerpt` (str)
- `detector/engine.py` exports an `analyze(text: str) -> dict` function
- `analyze()` returns: `verdict` (str), `score` (int), `confidence` (str), `warnings` (list), `explanation` (str)
- Score-to-verdict mapping: 0–29 → Potentially Legitimate, 30–59 → Suspicious, 60+ → Scam
- The five known test cases (see Testing section) return the expected verdicts

**Todo List:**
1. In `rules.py`, implement rule functions for each category below; each checks the lowercased text with `re` or string matching and returns a list of triggered warning dicts:
   - Urgency language: "act now", "limited time", "expires", "immediately", "urgent", "asap"
   - Too-good-to-be-true: "you've won", "you have won", "free gift", "claim your prize", "lottery", "selected"
   - Threat / fear: "account will be suspended", "legal action", "arrest", "verify or lose"
   - Impersonation keywords: "irs", "paypal", "microsoft support", "your bank", "netflix", "amazon security"
   - Credential harvesting: "verify your identity", "click to confirm", "enter your password", "login to verify"
   - Suspicious links: URLs containing an IP address, URL shorteners (bit.ly, tinyurl, t.co, ow.ly), or mismatched domains (use `urllib.parse` + `re`)
   - Informal / SMS patterns: excessive caps (>40% uppercase letters), three or more consecutive exclamation marks or question marks
2. Implement `run_all_rules(text)` to call all rule functions and return the combined flat list
3. In `engine.py`, implement `analyze(text)`:
   - Call `run_all_rules(text)`
   - Sum weights to produce `score`
   - Map score to `verdict` and `confidence` (Low / Medium / High based on score bands)
   - Build `explanation` string: "This message triggered N warning sign(s) commonly associated with [verdict type] messages."
   - Return the full result dict

**Relevant Context:**
- `detector/rules.py` — write here
- `detector/engine.py` — write here
- `detector/__init__.py` — no changes needed

**Status:** [ ] pending

---

## Sub-Task 3 — Flask Routes and JSON API

**Intent:** Wire the detector engine into Flask so the browser can submit a message and receive a structured JSON response. Keeps `app.py` thin.

**Expected Outcomes:**
- `GET /` renders `index.html`
- `POST /analyze` accepts `{"message": "..."}` JSON body, calls `engine.analyze()`, returns the result as JSON
- Returns HTTP 400 with `{"error": "No message provided"}` if the body is missing or empty
- No message content is logged or stored anywhere

**Todo List:**
1. In `app.py`, import `analyze` from `detector.engine`
2. Add `GET /` route: `return render_template("index.html")`
3. Add `POST /analyze` route:
   - Parse JSON body; extract `message` field
   - If missing or blank, return `jsonify({"error": "No message provided"}), 400`
   - Call `analyze(message)` and return `jsonify(result)`
4. Guard with `if __name__ == "__main__": app.run(debug=True)`

**Relevant Context:**
- `app.py` — write here
- `detector/engine.py` — already implemented in Sub-Task 2

**Status:** [ ] pending

---

## Sub-Task 4 — UI: Templates and Frontend

**Intent:** Build the single-page UI so users can paste a message, submit it, and immediately see the verdict badge, score, confidence level, and the full list of triggered warnings with excerpts.

**Expected Outcomes:**
- `base.html` provides the Bootstrap 5 CDN shell (no local download needed), navbar with "ScamShield AI" title, and a `{% block content %}` slot
- `index.html` extends `base.html` and contains:
  - A textarea (min 4 rows) labeled "Paste your message here"
  - A "Analyze" button
  - A hidden results card that becomes visible after analysis, containing:
    - Verdict badge (green for Legitimate, yellow for Suspicious, red for Scam)
    - Score and confidence label
    - Explanation sentence
    - Bulleted list of warnings: each shows the rule name and the excerpt in a `<code>` tag
  - A "Clear" button to reset the form
- `app.js` sends a `fetch` POST to `/analyze` with `Content-Type: application/json`, receives the response, and renders the results card without page reload; shows a loading spinner on the button while the request is in flight
- `custom.css` adds minimal card shadow and badge color overrides if Bootstrap defaults are insufficient

**Todo List:**
1. Write `base.html`: DOCTYPE, Bootstrap 5 CDN `<link>` and `<script>` tags, navbar, `{% block content %}{% endblock %}`, custom.css link, app.js script tag
2. Write `index.html`: form layout, results card (hidden by default with `d-none`), all required elements listed above
3. Write `app.js`:
   - On form submit: prevent default, show spinner, POST JSON to `/analyze`
   - On success: populate all result fields, remove `d-none` from results card
   - On error (HTTP 400 or network): show a dismissible Bootstrap alert with the error message
   - Clear button: reset textarea, re-hide results card, clear all populated fields
4. Write `custom.css`: card box-shadow, verdict badge color variables if needed

**Relevant Context:**
- `templates/base.html` — write here
- `templates/index.html` — write here
- `static/js/app.js` — write here
- `static/css/custom.css` — write here

**Status:** [ ] pending

---

## Sub-Task 5 — Phase 3 Placeholder: ML Classifier Stub

**Intent:** Add an empty, well-documented stub for the ML classifier so Phase 3 can be implemented cleanly later without redesigning `engine.py`. No ML logic is implemented yet.

**Expected Outcomes:**
- `detector/ml_classifier.py` exists with a documented `classify(text: str) -> dict` stub that raises `NotImplementedError`
- A comment in `engine.py` shows exactly where the ML probability would be blended in
- A `detector/train.py` stub exists with instructions for Phase 3

**Todo List:**
1. Create `detector/ml_classifier.py` with a `classify(text)` stub and a docstring explaining the Phase 3 contract: returns `{"label": str, "probability": float}`
2. Add a commented block in `engine.py` after the score calculation showing where `ml_classifier.classify(text)` would be called to adjust the score
3. Create `detector/train.py` with a header comment describing: download SMS Spam Collection CSV from UCI, run this script to train and save a `joblib` model

**Relevant Context:**
- `detector/engine.py` — add comment block
- `detector/ml_classifier.py` — create
- `detector/train.py` — create

**Status:** [ ] pending

---

## Testing

### Manual Test Cases

| Input | Expected Verdict |
|---|---|
| "Your package is ready for delivery. Track at usps.com." | Potentially Legitimate |
| "URGENT: Your Netflix account is suspended. Verify at netflix-support.xyz NOW!!!" | Scam |
| "Hi, just checking if you're free for lunch tomorrow?" | Potentially Legitimate |
| "Congratulations! You've been selected for a FREE iPhone. Claim at bit.ly/xyz" | Scam |
| "Your Amazon order has shipped. Estimated delivery Thursday." | Potentially Legitimate |

### How to Run

```powershell
cd scamshield
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
flask --app app run --debug
# Open http://127.0.0.1:5000
```

### Unit Tests (optional, no extra packages)

Add `tests/test_engine.py` using Python's built-in `unittest`. Each test passes a known string to `engine.analyze()` and asserts the expected `verdict` field. Run with `python -m unittest discover tests`.

---

## Dependencies

| Package | Phase | Source |
|---|---|---|
| `flask` | 1+ | `pip install flask` |
| `re`, `urllib.parse` | 2 | Python standard library — no install |
| `scikit-learn` | 3 | `pip install scikit-learn` |
| `pandas` | 3 | `pip install pandas` |
| `joblib` | 3 | `pip install joblib` |

Bootstrap 5 is loaded from CDN in the HTML template — no npm or Node.js required.

---

## Non-Goals

- User accounts, login, sessions
- Database of any kind
- Storing or logging submitted messages
- Sending data to any external service
- Deployment (cloud, Docker, WSGI server)
- Email sending or receiving
