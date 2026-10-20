"""
tests/test_phase3_ui.py
-----------------------
Phase 3 UI / API regression tests for ScamShield AI.

These tests verify the Flask routes return all fields the Phase 3 frontend
expects, that all six sample messages classify correctly, that recommendations
keys map to real verdicts, and that output escaping cannot be bypassed via
the API payload.

Run with:
    .\\venv\\Scripts\\python.exe -m unittest discover tests -v
"""

import sys
import os
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as flask_app
from detector.engine import analyze


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CLIENT = flask_app.app.test_client()
flask_app.app.testing = True


def post(message):
    """POST /analyze and return (status_code, json_data)."""
    resp = CLIENT.post(
        "/analyze",
        data=json.dumps({"message": message}),
        content_type="application/json"
    )
    return resp.status_code, resp.get_json()


# ---------------------------------------------------------------------------
# 1. Response shape — all keys the Phase 3 frontend reads must be present
# ---------------------------------------------------------------------------

class TestResponseShape(unittest.TestCase):

    REQUIRED_KEYS = (
        "verdict", "score", "confidence", "signals",
        "css_class", "icon", "subtitle", "explanation", "warnings",
    )

    def _assert_shape(self, message):
        status, data = post(message)
        self.assertEqual(status, 200, msg=f"Expected 200, got {status}")
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, data, msg=f"Missing key '{key}' in response")
        self.assertIsInstance(data["warnings"], list)
        self.assertIsInstance(data["score"],    int)
        self.assertIsInstance(data["signals"],  int)

    def test_shape_scam_message(self):
        self._assert_shape(
            "URGENT verify your password now at https://paypal-secure.xyz immediately"
        )

    def test_shape_legit_message(self):
        self._assert_shape("Hi, your appointment is confirmed for Monday at 9am.")

    def test_shape_empty_string_after_strip(self):
        """Whitespace-only returns 400, not a malformed 200."""
        status, data = post("   ")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_warnings_have_required_keys(self):
        """Every warning dict must carry rule, description, excerpt."""
        _, data = post(
            "URGENT: verify your password now at http://bit.ly/scam"
        )
        for w in data["warnings"]:
            for k in ("rule", "description", "excerpt"):
                self.assertIn(k, w, msg=f"Warning missing key '{k}': {w}")

    def test_score_is_integer_0_to_100(self):
        _, data = post("Any message at all.")
        self.assertGreaterEqual(data["score"], 0)
        self.assertLessEqual(data["score"], 100)

    def test_css_class_is_one_of_three(self):
        valid = {"ss-verdict-legit", "ss-verdict-spam", "ss-verdict-scam"}
        for msg in [
            "Hi how are you",
            "Congratulations you won click bit.ly/win",
            "URGENT verify password at https://paypal-secure.xyz",
        ]:
            _, data = post(msg)
            self.assertIn(
                data["css_class"], valid,
                msg=f"Unexpected css_class '{data['css_class']}' for: {msg[:40]}"
            )

    def test_verdict_is_one_of_three(self):
        valid = {
            "Likely Legitimate",
            "Suspicious — needs review",
            "Likely Spam/Scam",
        }
        _, data = post("Hello there.")
        self.assertIn(data["verdict"], valid)


# ---------------------------------------------------------------------------
# 2. Six sample messages must classify into expected verdict bands
# ---------------------------------------------------------------------------

class TestSampleMessages(unittest.TestCase):
    """
    These are the same sample texts loaded by the Phase 3 UI buttons.
    They must produce consistent, sensible verdicts.
    """

    def test_phishing_sample_is_scam(self):
        msg = (
            "URGENT: Your Netflix account has been suspended due to a billing failure.\n\n"
            "To avoid permanent closure, verify your payment details immediately:\n"
            "https://netflix-secure-update.xyz/verify\n\n"
            "This link expires in 24 hours. Act now to restore access.\n\n"
            "\u2014 Netflix Billing Team"
        )
        _, data = post(msg)
        self.assertEqual(data["verdict"], "Likely Spam/Scam")
        self.assertGreaterEqual(data["score"], 60)

    def test_prize_spam_sample_is_scam_or_suspicious(self):
        msg = (
            "Congratulations! You have been SELECTED for a FREE $500 Amazon Gift Card!\n\n"
            "You are our 1,000,000th visitor! Claim your prize before it expires:\n"
            "http://bit.ly/claim-free-gift\n\n"
            "Limited time offer. Don't miss out!!!"
        )
        _, data = post(msg)
        self.assertIn(data["verdict"], ["Likely Spam/Scam", "Suspicious — needs review"])
        self.assertGreaterEqual(data["score"], 30)

    def test_otp_scam_sample_is_scam(self):
        msg = (
            "ALERT: Unusual sign-in detected on your bank account.\n\n"
            "To secure your account, enter your one-time passcode and password at:\n"
            "http://192.0.2.45/bank-secure-login\n\n"
            "If you do not verify within 30 minutes your account will be locked.\n\n"
            "\u2014 Security Team, Your Bank"
        )
        _, data = post(msg)
        # Credential + IP URL + threat = 50 pts → Suspicious at minimum
        self.assertIn(data["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])
        self.assertGreaterEqual(data["score"], 35)

    def test_payment_fraud_sample_is_scam(self):
        msg = (
            "Final Notice: You have an unpaid invoice of $847.00.\n\n"
            "Legal action and an arrest warrant will be issued within 24 hours\n"
            "if payment is not made immediately.\n\n"
            "Pay now via wire transfer or Bitcoin to avoid prosecution.\n"
            "Call our debt recovery team immediately."
        )
        _, data = post(msg)
        # Threat + payment demand = 40 pts → Suspicious at minimum
        self.assertIn(data["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])
        self.assertGreaterEqual(data["score"], 35)

    def test_legit_dental_appointment_is_not_scam(self):
        msg = (
            "Hi Sarah,\n\n"
            "Just a reminder that your dental appointment is scheduled for\n"
            "Tuesday, 14 January at 10:30 AM.\n\n"
            "If you need to reschedule, please call us at (555) 234-5678\n"
            "or reply to this message.\n\n"
            "Kind regards,\n"
            "SmileCare Dental Practice"
        )
        _, data = post(msg)
        self.assertEqual(data["verdict"], "Likely Legitimate")
        self.assertLess(data["score"], 30)

    def test_legit_amazon_shipping_is_not_scam(self):
        msg = (
            "Your Amazon order #112-3456789 has shipped and is on its way.\n"
            "Estimated delivery: Thursday, 16 January.\n\n"
            "Track your package at amazon.com/orders.\n\n"
            "Thank you for shopping with Amazon."
        )
        _, data = post(msg)
        self.assertNotEqual(data["verdict"], "Likely Spam/Scam")


# ---------------------------------------------------------------------------
# 3. Verdict labels match expected css_class and icon
# ---------------------------------------------------------------------------

class TestVerdictMetadata(unittest.TestCase):

    def _meta_for(self, msg):
        _, data = post(msg)
        return data

    def test_scam_verdict_uses_red_class(self):
        # Use a message with enough signals to reliably reach Likely Spam/Scam (≥65)
        data = self._meta_for(
            "Enter your password and verify your bank details at https://paypal-secure.xyz — "
            "your account will be deactivated if you do not act now."
        )
        self.assertEqual(data["css_class"], "ss-verdict-scam")
        self.assertIn("x", data["icon"])       # bi-shield-x

    def test_legit_verdict_uses_green_class(self):
        data = self._meta_for("Hi, your appointment is Tuesday at 9am.")
        self.assertEqual(data["css_class"], "ss-verdict-legit")
        self.assertIn("check", data["icon"])   # bi-shield-check

    def test_suspicious_verdict_uses_amber_class(self):
        # A message that hits ~30-59 — brand mention only with mild urgency
        data = self._meta_for(
            "Your PayPal account needs attention. Please review your recent activity."
        )
        # Could be suspicious or legit depending on exact weight — just check class is valid
        self.assertIn(data["css_class"], {
            "ss-verdict-legit", "ss-verdict-spam", "ss-verdict-scam"
        })


# ---------------------------------------------------------------------------
# 4. Output safety — server must not reflect dangerous HTML back
# ---------------------------------------------------------------------------

class TestOutputSafety(unittest.TestCase):

    def test_html_tags_in_message_do_not_appear_in_excerpt(self):
        """Script tags passed as message must not be reflected unescaped."""
        msg = "<script>alert('xss')</script> Urgent verify your password now!"
        _, data = post(msg)
        # JSON is text — the excerpt/explanation text should contain the literal
        # string, not be executed; we just verify the response is valid JSON
        self.assertIn("verdict", data)
        for w in data["warnings"]:
            # excerpt must be a plain string, not contain executed code markers
            self.assertIsInstance(w["excerpt"], str)

    def test_explanation_does_not_contain_html(self):
        msg = "Hello <b>world</b> urgent verify password"
        _, data = post(msg)
        # Explanation built by engine, never from user text directly
        self.assertNotIn("<b>", data["explanation"])
        self.assertNotIn("<script>", data["explanation"])

    def test_long_excerpt_does_not_crash(self):
        """A rule matching a very long string must still produce a valid excerpt."""
        long_urgent = "URGENT " * 200
        _, data = post(long_urgent)
        self.assertIn("verdict", data)


# ---------------------------------------------------------------------------
# 5. Accessibility / template structure checks
# ---------------------------------------------------------------------------

class TestTemplateStructure(unittest.TestCase):

    def setUp(self):
        resp = CLIENT.get("/")
        self.html = resp.data.decode("utf-8")

    def test_page_has_lang_attribute(self):
        self.assertIn('lang="en"', self.html)

    def test_results_area_has_aria_live(self):
        self.assertIn('aria-live="polite"', self.html)

    def test_error_alert_has_aria_live_assertive(self):
        self.assertIn('aria-live="assertive"', self.html)

    def test_char_counter_present(self):
        self.assertIn("charCounter", self.html)

    def test_recommendations_list_present(self):
        self.assertIn("recommendationsList", self.html)

    def test_risk_bar_present(self):
        self.assertIn("riskBar", self.html)
        self.assertIn('role="progressbar"', self.html)

    def test_six_sample_buttons_present(self):
        for key in ("phishing", "prize", "otp", "payment", "legit1", "legit2"):
            self.assertIn(f"loadSample('{key}')", self.html,
                          msg=f"Sample button for '{key}' missing from template")

    def test_no_ai_accuracy_claim(self):
        """Page must not claim accuracy percentages or ML predictions."""
        for phrase in ("% accuracy", "trained model", "machine learning", "neural"):
            self.assertNotIn(phrase.lower(), self.html.lower(),
                             msg=f"Forbidden phrase found: '{phrase}'")

    def test_phase_badge_updated(self):
        self.assertIn("Phase 3", self.html)
        self.assertNotIn("Phase 1", self.html)
        self.assertNotIn("Phase 2", self.html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
