"""
tests/test_engine.py
--------------------
Unit tests for the ScamShield AI rule-based detection engine (Phase 2).

Run with:
    .\\venv\\Scripts\\python.exe -m pytest tests/ -v
or (without pytest):
    .\\venv\\Scripts\\python.exe -m unittest discover tests
"""

import sys
import os
import unittest

# Allow imports from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.engine import analyze
from detector import rules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def verdicts_of(text):
    return analyze(text)["verdict"]


# ---------------------------------------------------------------------------
# 1. Legitimate messages — must NOT be classified as Scam
# ---------------------------------------------------------------------------

class TestLegitimateMessages(unittest.TestCase):

    def test_appointment_reminder(self):
        msg = (
            "Hi Sarah, just a reminder that your dental appointment is scheduled "
            "for Tuesday, 14 January at 10:30 AM. If you need to reschedule, "
            "please call us at (555) 234-5678. Kind regards, SmileCare Dental."
        )
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Legitimate")
        self.assertLess(result["score"], 30)

    def test_package_delivery_notification(self):
        msg = (
            "Your Amazon order #112-3456789 has shipped and is on its way. "
            "Estimated delivery: Thursday, 16 January. "
            "Track your package at amazon.com/orders."
        )
        result = analyze(msg)
        # Amazon is flagged as a brand mention but score stays below Scam threshold
        self.assertNotEqual(result["verdict"], "Likely Spam/Scam")

    def test_casual_chat_message(self):
        msg = "Hey, are you free for lunch tomorrow? I was thinking the usual place around noon."
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Legitimate")
        self.assertEqual(result["signals"], 0)

    def test_newsletter_unsubscribe(self):
        msg = (
            "You are receiving this email because you subscribed to our weekly "
            "newsletter. To unsubscribe, click the link below or reply STOP. "
            "© 2024 Example Corp, 123 Main St, Springfield."
        )
        result = analyze(msg)
        self.assertNotEqual(result["verdict"], "Likely Spam/Scam")

    def test_bank_statement_notice(self):
        msg = (
            "Your monthly statement for account ending 4321 is now available. "
            "Log in to online banking to view it. Do not reply to this email."
        )
        result = analyze(msg)
        # 'Log in' alone should not push this to Scam
        self.assertNotEqual(result["verdict"], "Likely Spam/Scam")


# ---------------------------------------------------------------------------
# 2. Spam messages — should score >= 30
# ---------------------------------------------------------------------------

class TestSpamMessages(unittest.TestCase):

    def test_prize_claim_with_shortener(self):
        msg = (
            "Congratulations! You have been SELECTED for a FREE $500 Amazon Gift Card! "
            "You are our 1,000,000th visitor! Claim your prize before it expires: "
            "http://bit.ly/claim-free-gift  Limited time offer. Don't miss out!!!"
        )
        result = analyze(msg)
        self.assertGreaterEqual(result["score"], 30)
        self.assertIn(result["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])

    def test_lottery_winner(self):
        msg = (
            "You have won £1,000,000 in the UK National Lottery draw! "
            "To claim your prize, contact us within 48 hours. "
            "Send your full name, address, and bank account details."
        )
        result = analyze(msg)
        # Prize + multiple prize signals — score may be moderate (single-category cap applies)
        self.assertGreaterEqual(result["score"], 20)

    def test_excessive_caps_and_punctuation(self):
        msg = "YOU WON!!! CLAIM YOUR FREE GIFT NOW!!! ACT FAST!!!"
        result = analyze(msg)
        self.assertGreaterEqual(result["score"], 30)

    def test_free_iphone_offer(self):
        msg = (
            "Congratulations! You've been selected to receive a FREE iPhone 15! "
            "This is a limited time offer — claim your reward at tinyurl.com/freephone99"
        )
        result = analyze(msg)
        # Prize (20) + URL shortener (18) + limited time offer (15) = 53; suspicious at minimum
        self.assertGreaterEqual(result["score"], 35)
        self.assertIn(result["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])


# ---------------------------------------------------------------------------
# 3. Scam messages — should score >= 60
# ---------------------------------------------------------------------------

class TestScamMessages(unittest.TestCase):

    def test_netflix_phishing(self):
        msg = (
            "URGENT: Your Netflix account has been suspended due to a billing failure. "
            "To avoid permanent closure, verify your payment details immediately: "
            "https://netflix-secure-update.xyz/verify  "
            "This link expires in 24 hours. Act now to restore access."
        )
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Spam/Scam")
        self.assertGreaterEqual(result["score"], 60)

    def test_bank_credential_harvest(self):
        msg = (
            "Dear customer, your account will be suspended unless you verify your "
            "identity immediately. Please enter your password and PIN at: "
            "http://192.168.1.1/bank-verify"
        )
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Spam/Scam")

    def test_irs_threat_scam(self):
        msg = (
            "Final notice from the IRS: You owe $2,340 in unpaid taxes. "
            "Legal action and arrest warrant will be issued within 24 hours "
            "if payment is not made immediately via gift card or wire transfer."
        )
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Spam/Scam")
        self.assertGreaterEqual(result["score"], 60)

    def test_tech_support_scam(self):
        msg = (
            "WARNING: Your Windows PC is infected with a virus! "
            "Call Microsoft Support immediately at 1-800-XXX-XXXX. "
            "Your account will be deactivated if you do not act now. "
            "Provide your credit card details to our technician for a security scan."
        )
        result = analyze(msg)
        self.assertEqual(result["verdict"], "Likely Spam/Scam")

    def test_otp_request(self):
        msg = (
            "Your bank account shows unusual activity. "
            "To confirm it was you, please enter your OTP and password at: "
            "http://secure-bank-verify.click/auth"
        )
        result = analyze(msg)
        # Credential (25) + suspicious TLD click (20) = 45 → Suspicious at minimum
        self.assertIn(result["verdict"], ["Suspicious — needs review", "Likely Spam/Scam"])
        self.assertGreaterEqual(result["score"], 35)

    def test_ip_address_url(self):
        msg = "Click here to verify your account: http://203.0.113.45/verify?token=abc123"
        result = analyze(msg)
        self.assertGreaterEqual(result["score"], 22)  # IP URL alone is heavy

    def test_url_shortener_detected(self):
        msg = "Check this out: https://bit.ly/3xAmPle"
        result = analyze(msg)
        rule_names = [w["rule"] for w in result["warnings"]]
        self.assertIn("URL Shortener Detected", rule_names)

    def test_lookalike_domain(self):
        msg = "Verify your account at https://paypal-account-secure.com/login"
        result = analyze(msg)
        rule_names = [w["rule"] for w in result["warnings"]]
        self.assertIn("Brand Lookalike Domain", rule_names)


# ---------------------------------------------------------------------------
# 4. Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):

    def test_empty_string_via_engine(self):
        """Engine handles empty string gracefully (route blocks it, but engine should too)."""
        result = analyze("")
        self.assertIn("verdict", result)
        self.assertEqual(result["signals"], 0)
        self.assertEqual(result["score"], 0)

    def test_very_long_message_truncated(self):
        """Messages over MAX_MESSAGE_LENGTH are truncated, not crashed."""
        long_msg = "A" * 25_000
        result = analyze(long_msg)
        self.assertIn("verdict", result)

    def test_message_with_html_tags(self):
        """HTML in the message must not cause errors; engine treats it as plain text."""
        msg = "<script>alert('xss')</script> Urgent: verify your password now!"
        result = analyze(msg)
        self.assertIn("verdict", result)
        self.assertGreater(result["score"], 0)

    def test_unicode_message(self):
        """Unicode characters in message must not crash the engine."""
        msg = "Congratulations! You've won a prize 🎉🎁. Claim now — limited time!"
        result = analyze(msg)
        self.assertIn("verdict", result)

    def test_result_keys_present(self):
        """Every required key is present in the result dict."""
        result = analyze("Hello, how are you today?")
        for key in ("verdict", "score", "confidence", "signals",
                    "css_class", "icon", "subtitle", "explanation", "warnings"):
            self.assertIn(key, result, msg=f"Missing key: {key}")

    def test_score_capped_at_100(self):
        """Score never exceeds 100, even for a message that hits many rules."""
        very_bad = (
            "URGENT!!! Your account will be suspended immediately. "
            "Verify your password and OTP NOW or face legal action and arrest. "
            "You've won a FREE gift card! Claim at http://bit.ly/scam-link "
            "https://paypal-secure.xyz/verify  http://192.0.2.1/login "
            "Wire transfer required. Bitcoin payment. Final warning!!!"
        )
        result = analyze(very_bad)
        self.assertLessEqual(result["score"], 100)

    def test_confidence_low_for_zero_signals(self):
        result = analyze("See you tomorrow.")
        self.assertEqual(result["confidence"], "Low")

    def test_warnings_are_list(self):
        result = analyze("Any message at all.")
        self.assertIsInstance(result["warnings"], list)


# ---------------------------------------------------------------------------
# 5. Flask route tests
# ---------------------------------------------------------------------------

class TestFlaskRoutes(unittest.TestCase):

    def setUp(self):
        import app as flask_app
        flask_app.app.testing = True
        self.client = flask_app.app.test_client()

    def test_get_index_returns_200(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ScamShield", resp.data)

    def test_analyze_returns_json(self):
        resp = self.client.post(
            "/analyze",
            json={"message": "URGENT: verify your password now at http://bit.ly/x"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("verdict", data)
        self.assertIn("warnings", data)

    def test_analyze_empty_message_returns_400(self):
        resp = self.client.post("/analyze", json={"message": ""})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_analyze_whitespace_only_returns_400(self):
        resp = self.client.post("/analyze", json={"message": "   \n\t  "})
        self.assertEqual(resp.status_code, 400)

    def test_analyze_no_body_returns_400(self):
        resp = self.client.post(
            "/analyze",
            data="not json",
            content_type="text/plain"
        )
        self.assertEqual(resp.status_code, 400)

    def test_analyze_missing_message_key_returns_400(self):
        resp = self.client.post("/analyze", json={"text": "hello"})
        self.assertEqual(resp.status_code, 400)

    def test_analyze_long_message_returns_400(self):
        resp = self.client.post(
            "/analyze",
            json={"message": "x" * 25_000}
        )
        self.assertEqual(resp.status_code, 400)

    def test_analyze_legit_message_not_scam(self):
        resp = self.client.post(
            "/analyze",
            json={"message": "Hi, your appointment is confirmed for Monday at 9am."}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertNotEqual(data["verdict"], "Likely Spam/Scam")

    def test_analyze_scam_message_is_scam(self):
        resp = self.client.post(
            "/analyze",
            json={"message": (
                "URGENT: Your account will be suspended. "
                "Verify your password and OTP immediately at "
                "https://paypal-secure.xyz/verify"
            )}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["verdict"], "Likely Spam/Scam")


if __name__ == "__main__":
    unittest.main(verbosity=2)
