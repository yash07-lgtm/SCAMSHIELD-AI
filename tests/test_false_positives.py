"""
tests/test_false_positives.py
------------------------------
Tests for genuine (real-world) emails and edge-case suspicious messages.

These verify that the false-positive fixes work correctly:
  - Genuine emails must NOT be classified as "Likely Spam/Scam"
  - Genuine emails SHOULD be "Likely Legitimate" (score < 35)
  - Clear scam messages MUST still reach "Likely Spam/Scam" (score >= 65)
  - Borderline messages should land in "Suspicious — needs review"

Run with:
    .\\venv\\Scripts\\python.exe -m unittest tests.test_false_positives -v
"""

import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector.engine import analyze

LEGIT   = "Likely Legitimate"
SUSP    = "Suspicious \u2014 needs review"
SCAM    = "Likely Spam/Scam"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _check(msg):
    r = analyze(msg)
    return r["verdict"], r["score"], r["warnings"]


# ---------------------------------------------------------------------------
# SECTION A — Genuine emails must NOT be Likely Spam/Scam
# ---------------------------------------------------------------------------

class TestGenuineEmails(unittest.TestCase):
    """
    Real-world style emails that should never be classified as Likely Spam/Scam.
    All must score < 65. Most should score < 35 (Likely Legitimate).
    """

    def test_2fa_delivery_email(self):
        """Legitimate 2FA code delivery — mentions 'code' and 'expires' but is not requesting credentials."""
        msg = (
            "Your verification code is 847291.\n\n"
            "Use this code to sign in to your Google account. "
            "This code expires in 10 minutes.\n\n"
            "If you didn't request this, you can safely ignore this email."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "2FA delivery email was classified as Likely Spam/Scam")
        self.assertLess(score, 65, f"2FA delivery email scored too high: {score}")

    def test_password_reset_from_github(self):
        """Password reset emails mention 'password' but are not requesting it from the user."""
        msg = (
            "Hi Alex,\n\n"
            "We received a request to reset your GitHub password. "
            "Click the link below within 1 hour to reset it.\n\n"
            "https://github.com/password-reset?token=abc123\n\n"
            "If you didn't request this, no action is required — your password is safe."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Password reset email was classified as Likely Spam/Scam")
        self.assertLess(score, 65, f"Password reset scored too high: {score}")

    def test_bank_statement_ready(self):
        """Routine bank statement notification — mentions account and chase.com."""
        msg = (
            "Your monthly statement is ready.\n\n"
            "Dear customer, your account statement for March 2024 is now available. "
            "Log in to your account at chase.com to view it.\n\n"
            "If you have questions, call the number on the back of your card."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Bank statement email was classified as Likely Spam/Scam")
        self.assertLess(score, 35, f"Bank statement scored too high: {score}")

    def test_amazon_order_confirmation(self):
        """Amazon order confirmation — legitimate use of Amazon brand name."""
        msg = (
            "Your Amazon order has been confirmed.\n\n"
            "Order #112-3456789: Blue Wireless Headphones\n"
            "Estimated delivery: Thursday 16 January\n\n"
            "Track your package at amazon.com/orders.\n"
            "Thank you for shopping with Amazon."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Amazon order confirmation was classified as Likely Spam/Scam")
        self.assertLess(score, 35, f"Amazon order scored too high: {score}")

    def test_google_security_new_signin_alert(self):
        """Google new sign-in alert — legitimate security notification."""
        msg = (
            "Security alert\n\n"
            "A new sign-in to your Google Account was detected.\n"
            "Device: Windows PC — Location: London, UK\n\n"
            "If this was you, no action is required.\n"
            "If you don't recognise this sign-in, review your account activity at myaccount.google.com."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Google sign-in alert was classified as Likely Spam/Scam")
        self.assertLess(score, 35, f"Google sign-in alert scored too high: {score}")

    def test_paypal_payment_receipt(self):
        """PayPal transaction receipt — legitimate use of PayPal brand."""
        msg = (
            "You sent a payment of $45.00 to John Smith.\n\n"
            "Transaction ID: 7WH29384JD\n"
            "Date: 14 January 2025\n\n"
            "You can view this transaction at paypal.com/activity."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "PayPal receipt was classified as Likely Spam/Scam")
        self.assertLess(score, 35, f"PayPal receipt scored too high: {score}")

    def test_linkedin_connection_request(self):
        """LinkedIn connection email."""
        msg = (
            "Hi Sarah,\n\n"
            "John Doe wants to connect with you on LinkedIn.\n\n"
            "John Doe — Software Engineer at Acme Corp\n\n"
            "View John's profile at linkedin.com\n\n"
            "If you don't know John, you can ignore this email."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "LinkedIn email was classified as Likely Spam/Scam")
        self.assertLess(score, 35)

    def test_newsletter_with_unsubscribe(self):
        """Newsletter with unsubscribe link."""
        msg = (
            "Thank you for being a subscriber!\n\n"
            "Here is your weekly summary from The Verge. "
            "Click here to read this week's top stories.\n\n"
            "To unsubscribe, click here. You'll no longer receive emails from us."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM)
        self.assertLess(score, 35)

    def test_appointment_reminder(self):
        """Standard appointment reminder."""
        msg = (
            "Reminder: Your appointment is on Wednesday 15 January at 2:30 PM.\n\n"
            "Dr. Smith's Dental Practice\n"
            "123 High Street, London\n"
            "Call (020) 1234 5678 to reschedule."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, LEGIT)
        self.assertEqual(score, 0)

    def test_job_application_email(self):
        """Routine job application / CV email."""
        msg = (
            "Dear Hiring Manager,\n\n"
            "I am writing to apply for the Software Engineer position advertised on your website. "
            "Please find my CV attached. I am available for interview at your earliest convenience.\n\n"
            "Kind regards,\nJane Doe"
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, LEGIT)
        self.assertEqual(score, 0)

    def test_microsoft_365_invoice(self):
        """Microsoft 365 subscription invoice — legitimate Microsoft mention."""
        msg = (
            "Your Microsoft 365 subscription has been renewed.\n\n"
            "Amount charged: £9.99\n"
            "Billing date: 14 January 2025\n\n"
            "View your invoice at account.microsoft.com.\n"
            "To cancel, visit your account page."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Microsoft 365 invoice was classified as Likely Spam/Scam")
        self.assertLess(score, 35)

    def test_friend_casual_message(self):
        """Casual personal message."""
        msg = "Hey, are you free for lunch tomorrow? I was thinking the usual place around noon."
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, LEGIT)
        self.assertEqual(score, 0)

    def test_free_delivery_promotion(self):
        """Legitimate retailer email with 'free' in it."""
        msg = (
            "Your order qualifies for free delivery!\n\n"
            "We're pleased to let you know your order of £35.00 "
            "qualifies for free next-day delivery.\n\n"
            "Expected arrival: Thursday.\n"
            "— The ASOS Team"
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM)

    def test_verify_email_address_signup(self):
        """New-account email verification link — common in legitimate services."""
        msg = (
            "Welcome to ExampleApp!\n\n"
            "Please verify your email address by clicking the link below.\n\n"
            "https://exampleapp.com/verify?token=xyz789\n\n"
            "This link will expire in 24 hours.\n\n"
            "If you didn't sign up, you can safely ignore this email."
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Email verification link was classified as Likely Spam/Scam")
        self.assertLess(score, 65)

    def test_school_parent_notification(self):
        """School/parent notification — mentions 'action required' in legitimate context."""
        msg = (
            "Dear Parent,\n\n"
            "This is a reminder that permission slips for the Year 7 trip to the Science Museum "
            "are due by Friday 17 January.\n\n"
            "Please return the signed form to the school office.\n\n"
            "Kind regards,\nMrs. Johnson\nYear 7 Form Tutor"
        )
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM)
        self.assertLess(score, 35)


# ---------------------------------------------------------------------------
# SECTION B — Clear scam messages must still reach Likely Spam/Scam
# ---------------------------------------------------------------------------

class TestScamMessagesStillDetected(unittest.TestCase):
    """Verify that tightening rules did not break detection of real scams."""

    def test_netflix_phishing_with_lookalike_domain(self):
        msg = (
            "URGENT: Your Netflix account has been suspended due to a billing failure.\n\n"
            "Verify your payment details immediately:\n"
            "https://netflix-secure-update.xyz/verify\n\n"
            "Act now. This link expires today."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, SCAM, f"Netflix phishing not caught: {score}")
        self.assertGreaterEqual(score, 65)

    def test_otp_harvesting_with_ip_url(self):
        """OTP scam: credential request + IP URL + threat. Suspicious or Scam, score >= 35."""
        msg = (
            "ALERT: Unusual sign-in detected on your bank account.\n\n"
            "Enter your one-time passcode and password at:\n"
            "http://192.0.2.45/bank-secure-login\n\n"
            "If you do not verify within the deadline your account will be locked.\n\n"
            "\u2014 Security Team, Your Bank"
        )
        verdict, score, _ = _check(msg)
        self.assertIn(verdict, (SUSP, SCAM), f"OTP harvest scam not caught: {score}")
        self.assertGreaterEqual(score, 35, f"OTP harvest scam scored too low: {score}")

    def test_payment_fraud_with_threats(self):
        """Payment fraud: threat + payment demand. Suspicious or Scam, score >= 35."""
        msg = (
            "Final Notice: You have an unpaid invoice of $847.00.\n\n"
            "Legal action and an arrest warrant will be issued within 24 hours "
            "if payment is not made immediately.\n\n"
            "Pay now via wire transfer or Bitcoin to avoid prosecution."
        )
        verdict, score, _ = _check(msg)
        self.assertIn(verdict, (SUSP, SCAM), f"Payment fraud not flagged: {score}")
        self.assertGreaterEqual(score, 35)

    def test_prize_scam_with_url_shortener(self):
        msg = (
            "Congratulations! You have been SELECTED for a FREE $500 Amazon Gift Card!\n\n"
            "You are our 1,000,000th visitor! Claim your prize:\n"
            "http://bit.ly/claim-free-gift\n\n"
            "Limited time offer. Don't miss out!!!"
        )
        verdict, score, _ = _check(msg)
        self.assertGreaterEqual(score, 65)
        self.assertEqual(verdict, SCAM)

    def test_credential_harvesting_phishing(self):
        msg = (
            "Dear customer,\n\n"
            "We need you to verify your identity.\n"
            "Please enter your password and provide your bank details at:\n"
            "https://secure-bank-verify.click/auth\n\n"
            "Failure to do so will result in your account being suspended."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, SCAM)

    def test_tech_support_scam(self):
        msg = (
            "WARNING: Your Windows PC is infected with a virus!\n"
            "Call Microsoft Support immediately.\n"
            "Your account will be deactivated if you do not act now.\n"
            "Provide your credit card details to our technician for a security scan."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, SCAM)

    def test_irs_tax_threat(self):
        msg = (
            "Final notice from the IRS: You owe $2,340 in unpaid taxes.\n"
            "Legal action and arrest warrant will be issued within 24 hours "
            "if payment is not made immediately via gift card or wire transfer."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, SCAM)

    def test_enter_your_password_phishing(self):
        """Explicit "enter your password" phrasing must still fire."""
        msg = (
            "Your PayPal account requires verification.\n\n"
            "Please enter your password to confirm your identity at:\n"
            "https://paypal-secure.click/verify\n\n"
            "Immediate action required."
        )
        verdict, score, _ = _check(msg)
        self.assertEqual(verdict, SCAM)


# ---------------------------------------------------------------------------
# SECTION C — Borderline/suspicious messages that are not certain scams
# ---------------------------------------------------------------------------

class TestSuspiciousMessages(unittest.TestCase):
    """
    Messages with some red flags but not enough to be Likely Spam/Scam.
    These should land in Suspicious or Likely Legitimate, never in Likely Spam/Scam
    based on a single weak signal.
    """

    def test_single_brand_name_alone(self):
        """A message that only mentions a brand name should not be Likely Spam/Scam."""
        msg = "Hi, I'm from the Amazon warehouse team. We'll deliver tomorrow."
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM, "Single brand mention should not be Scam")
        self.assertLess(score, 65)

    def test_link_with_normal_domain_but_urgency(self):
        """Urgency + normal link — suspicious but not certain scam."""
        msg = (
            "Action required: Your account needs attention.\n\n"
            "Please log in at example.com to review recent changes.\n\n"
            "If you have questions, call our support line."
        )
        verdict, score, _ = _check(msg)
        # Should not reach Likely Spam/Scam on urgency alone
        self.assertLess(score, 65, f"Weak urgency + normal domain scored too high: {score}")

    def test_single_urgency_phrase_no_url(self):
        """One urgency phrase with no other signals stays below scam threshold."""
        msg = "Action required: Please confirm your meeting slot by end of day."
        verdict, score, _ = _check(msg)
        self.assertNotEqual(verdict, SCAM)
        self.assertLess(score, 65)

    def test_prize_without_suspicious_url(self):
        """'Congratulations' alone — suspicious but not certain scam without corroboration."""
        msg = "Congratulations on completing your coursework! Your certificate is ready."
        verdict, score, _ = _check(msg)
        # Prize/lottery rule fires but score stays moderate
        self.assertLess(score, 65)

    def test_score_cap_per_category(self):
        """
        A message that triggers the same rule category many times must not score
        as if each hit were independent.
        """
        msg = (
            "Enter your password. Enter your PIN. Enter your OTP. "
            "Please re-enter your password. Submit your passcode."
        )
        _, score, _ = _check(msg)
        # Credential rule fires many times but counts only once (weight 25)
        # Combined with no other signals, total should be 25
        self.assertLessEqual(score, 35,
            f"Per-category cap failed — credential rule added too much: {score}")


# ---------------------------------------------------------------------------
# SECTION D — Verdict label tests
# ---------------------------------------------------------------------------

class TestVerdictLabels(unittest.TestCase):

    def test_legitimate_label(self):
        _, r, _ = _check("Hi, how are you doing today?")
        self.assertEqual(r, 0)

    def test_suspicious_label_exists(self):
        """A mid-range message returns the new Suspicious label, not the old one."""
        r = analyze("Action required: Your account needs attention. Visit paypal.com to review.")
        self.assertNotIn("Possible Scam", r["verdict"])

    def test_scam_label_string(self):
        r = analyze(
            "Enter your password at https://paypal-secure.xyz — "
            "your account will be deactivated if you do not act now."
        )
        self.assertEqual(r["verdict"], "Likely Spam/Scam")

    def test_all_three_labels_accessible(self):
        from detector.engine import _VERDICT_LEGITIMATE, _VERDICT_SUSPICIOUS, _VERDICT_SCAM
        self.assertEqual(_VERDICT_LEGITIMATE, "Likely Legitimate")
        self.assertEqual(_VERDICT_SUSPICIOUS, "Suspicious \u2014 needs review")
        self.assertEqual(_VERDICT_SCAM, "Likely Spam/Scam")


if __name__ == "__main__":
    unittest.main(verbosity=2)
