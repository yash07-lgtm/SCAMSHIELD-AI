"""
detector/rules.py
-----------------
Rule-based heuristics for ScamShield AI.

Each rule function receives the original message text and returns a list of
zero or more warning dicts:

    {
        "rule":        str,   # human-readable rule name
        "description": str,   # plain-language explanation shown to the user
        "weight":      int,   # score contribution (capped once per category)
        "excerpt":     str,   # the exact substring that triggered the rule
    }

Design principles (false-positive reduction, updated):
- Rules match *requesting/threatening* phrases, not mere mentions of common words.
- Each rule category contributes its weight AT MOST ONCE to the total score,
  regardless of how many pattern matches fire within that category.
  (Multiple matches are still reported as separate warnings for transparency.)
- Bare words like "password", "urgent", "free", "verify", "account" do not score
  on their own — they need context (e.g. "enter your password", "urgent action
  required", "free gift card").
- Rules operate on a lower-cased copy of the text for matching but store the
  original-case excerpt for display.  No URLs are visited or resolved.
"""

import re

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_excerpts(text: str, patterns: list[str]) -> list[str]:
    """
    Return all non-overlapping substrings of *text* that match any pattern in
    *patterns* (case-insensitive).  Returns original-case excerpts.
    """
    found = []
    lower = text.lower()
    for pat in patterns:
        for m in re.finditer(pat, lower):
            found.append(text[m.start():m.end()])
    return found


# ---------------------------------------------------------------------------
# Individual rule functions
# ---------------------------------------------------------------------------

def rule_urgency(text: str) -> list[dict]:
    """
    Urgency / pressure-to-act-immediately language.

    Key change: removed bare ``\\bwithin\\s+\\d+\\s*(hours?|...)\\b`` which fires on
    legitimate password-reset and 2FA emails.  Retained only phrases that couple
    urgency with an imperative or threat context.
    """
    patterns = [
        # Multi-word imperative urgency phrases (less likely in genuine email)
        r"\bact\s+now\b",
        r"\bdon'?t\s+delay\b",
        r"\brespond\s+(now|immediately|asap)\b",
        r"\bfinal\s+(notice|warning)\b",
        r"\baction\s+required\b",
        r"\blast\s+chance\b",
        r"\blimited\s+time\s+offer\b",   # "offer" added — pure "limited time" is ok
        # "Urgent" must be paired: "urgent action", "urgent request", etc.
        r"\burgent\s+(action|request|matter|attention|warning|notice|update)\b",
        # Expiry framing that implies you must do something or lose access
        r"\blink\s+expires?\b",
        r"\bexpires?\s+(today|in\s+\d+\s*(hours?|minutes?))\s*[—\-,.]",
        r"\byour\s+access\s+will\s+(expire|be\s+revoked|be\s+terminated)\b",
        r"\bimmediate\s+(action|response|attention)\b",
        r"\bdeadline\s+to\s+(respond|act|verify|confirm)\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Urgency / Pressure",
            "description": (
                "The message uses urgent or time-pressure language to force a quick "
                "decision without giving you time to verify its legitimacy."
            ),
            "weight": 15,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_threats(text: str) -> list[dict]:
    """Threats of account suspension, legal action, or arrest."""
    patterns = [
        # Account actions framed as threats (not "your account statement is ready")
        r"\baccount\s+(will\s+be\s+|has\s+been\s+)(suspended|closed|terminated|blocked|locked)\b",
        r"\byour\s+account\s+(will|has\s+been)\s+(suspend|terminat|block|lock|clos)\w*\b",
        r"\blegal\s+action\b",
        r"\barrest(ed)?\b",
        r"\bprosecuted?\b",
        r"\bwarrant\b",
        r"\bpenalt(y|ies)\b",
        r"\bdeactivat(e|ed|ion)\b",
        r"\bverify\s+or\s+(lose|your\s+account\s+will)\b",
        # "suspended" alone is a high-signal word in threat context
        r"\b(account|service|access)\s+.{0,20}(suspended|terminated|revoked)\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Threat / Fear Tactic",
            "description": (
                "The message threatens negative consequences (account suspension, "
                "legal action, fines) to pressure you into acting without thinking."
            ),
            "weight": 20,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_credential_harvesting(text: str) -> list[dict]:
    """
    Requests for passwords, OTPs, PINs, or personal credentials.

    Key changes:
    - Removed bare r"\bpassword\b" — fires on "reset your password",
      "your password is safe", URL paths containing 'password'.
    - Removed bare r"\bpin\b" — too short, matches words like "PIN in your letter".
    - Removed bare r"\botp\b" — fires on legitimate 2FA delivery emails.
    - Replaced all bare words with *request-framing* phrases that indicate
      the sender is asking YOU to supply the credential (not delivering it to you).
    """
    patterns = [
        r"\benter\s+your\s+(password|pin|otp|passcode|code)\b",
        r"\bprovide\s+your\s+(password|pin|otp|passcode|verification\s+code)\b",
        r"\b(?:verify|confirm|validate|update|reset)\s+(?:your\s+)?(?:account\s+)?(?:password|passcode|otp|pin|security code)\b",
        # Other patterns...
        r"\bprovide\s+(?:your\s+)?(?:credit\s+)?card\s+(?:number|details?|information)\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Credential / Personal Info Request",
            "description": (
                "The message asks for sensitive information such as passwords, OTPs, "
                "PINs, or card details. Legitimate organisations never request these "
                "via email or SMS."
            ),
            "weight": 25,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_prize_lottery(text: str) -> list[dict]:
    """Unexpected prize, lottery, or gift claims."""
    patterns = [
        r"\byou'?ve?\s+(won|been\s+selected|been\s+chosen)\b",
        r"\byou\s+have\s+won\b",
        r"\bcongratulations?\b",
        r"\bprize\b",
        r"\blottery\b",
        r"\bgift\s+card\b",
        r"\bfree\s+(iphone|gift|reward|voucher|laptop|holiday|vacation|cash)\b",
        r"\bclaim\s+(your\s+)?(prize|reward|gift)\b",
        r"\bwinner\b",
        r"\bselected\s+(as\s+)?(a\s+)?winner\b",
        r"\bmillionth?\s+visitor\b",
        r"\b\d+(,\d{3})*\s*th\s+visitor\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Prize / Lottery Claim",
            "description": (
                "The message claims you have won a prize, lottery, or gift you never "
                "entered. This is a classic scam tactic used to steal personal "
                "information or money."
            ),
            "weight": 20,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_payment_demand(text: str) -> list[dict]:
    """Unexpected payment requests, invoice fraud, or fee-to-claim demands."""
    patterns = [
        r"\bpay\s+(now|immediately|today|this\s+fee)\b",
        r"\bunpaid\s+(invoice|bill|fee|charge)\b",
        r"\boutstanding\s+(balance|payment|invoice)\b",
        r"\bprocessing\s+fee\b",
        r"\brelease\s+fee\b",
        r"\bsmall\s+fee\b",
        r"\bwire\s+transfer\b",
        r"\bgift\s+card\s+(payment|code)\b",
        r"\bbitcoin\b",
        r"\bcryptocurrency\b",
        r"\bpayment\s+(required|needed|overdue)\b",
        r"\brefund\s+of\s+\$[\d,]+\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Unexpected Payment Demand",
            "description": (
                "The message demands payment, mentions overdue fees, or asks you to "
                "pay with unusual methods (gift cards, wire transfer, cryptocurrency). "
                "Legitimate organisations provide invoices through official channels."
            ),
            "weight": 20,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_impersonation(text: str) -> list[dict]:
    """
    Possible impersonation of well-known brands, banks, or government bodies.

    Weight kept low (8) — a brand name alone in a genuine email (e.g. a real
    PayPal receipt, a real Amazon order) should not trigger a high score.
    The weight only matters when combined with other suspicious signals.
    """
    patterns = [
        r"\bnetflix\b",
        r"\bpaypal\b",
        r"\bamazon\b",
        r"\bapple\b",
        r"\bmicrosoft\b",
        r"\bgoogle\b",
        r"\bfacebook\b",
        r"\binstagram\b",
        r"\bwhatsapp\b",
        r"\beba?y\b",
        r"\bdhl\b",
        r"\bfedex\b",
        r"\bups\b",
        r"\busps\b",
        r"\bhermes\b",
        r"\broya?l\s+mail\b",
        r"\bhmrc\b",
        r"\birs\b",
        r"\bssa\b",
        r"\bsocial\s+security\s+(administration|office)\b",
        r"\byour\s+bank\b",
        r"\bbarclays\b",
        r"\bnatwest\b",
        r"\blloyds\b",
        r"\bhsbc\b",
        r"\bchase\b",
        r"\bwells\s+fargo\b",
        r"\bcitibank\b",
        r"\bbank\s+of\s+america\b",
        r"\btech\s+support\b",
        r"\bmicrosoft\s+support\b",
        r"\bwindows\s+support\b",
    ]
    excerpts = _find_excerpts(text, patterns)
    return [
        {
            "rule": "Possible Brand Impersonation",
            "description": (
                "The message mentions a well-known company or government body. "
                "Always verify by going directly to the official website rather than "
                "clicking any link in the message."
            ),
            "weight": 8,
            "excerpt": e,
        }
        for e in excerpts
    ]


def rule_suspicious_links(text: str) -> list[dict]:
    """Suspicious URLs: IP addresses, URL shorteners, misleading domains."""
    warnings = []

    # URL shorteners
    shortener_pat = re.compile(
        r"https?://(bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|buff\.ly|"
        r"rebrand\.ly|short\.io|cutt\.ly|is\.gd|v\.gd|bl\.ink|tiny\.cc|"
        r"shorte\.st|adf\.ly|linktr\.ee)/\S*",
        re.IGNORECASE,
    )
    for m in shortener_pat.finditer(text):
        warnings.append({
            "rule": "URL Shortener Detected",
            "description": (
                "The message contains a shortened URL that hides the real destination. "
                "Scammers use URL shorteners to disguise malicious links."
            ),
            "weight": 18,
            "excerpt": m.group(),
        })

    # IP-address URLs
    ip_url_pat = re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/\S*)?",
        re.IGNORECASE,
    )
    for m in ip_url_pat.finditer(text):
        warnings.append({
            "rule": "IP Address URL",
            "description": (
                "The message contains a link using a raw IP address instead of a "
                "domain name. Legitimate services always use proper domain names."
            ),
            "weight": 22,
            "excerpt": m.group(),
        })

    # Suspicious TLDs
    misleading_pat = re.compile(
        r"https?://[a-z0-9\-]+\.(xyz|top|click|loan|work|date|"
        r"download|racing|win|party|faith|review|trade|cricket|science|"
        r"gq|cf|ml|ga|tk)[/\s\"']?",
        re.IGNORECASE,
    )
    for m in misleading_pat.finditer(text):
        warnings.append({
            "rule": "Suspicious Domain Extension",
            "description": (
                "The link uses a domain extension (.xyz, .top, .click, etc.) that is "
                "frequently associated with spam and phishing sites."
            ),
            "weight": 20,
            "excerpt": m.group().rstrip("\"' "),
        })

    # Brand lookalike domains (hyphenated or unofficial)
    brands = (
        r"(netflix|paypal|amazon|apple|microsoft|google|facebook|"
        r"instagram|ebay|dhl|fedex|ups|usps|barclays|natwest|lloyds|"
        r"hsbc|chase|wellsfargo|citibank)"
    )
    lookalike_pat = re.compile(
        r"https?://[a-z0-9]*" + brands + r"[a-z0-9\-]*\.[a-z]{2,}",
        re.IGNORECASE,
    )
    for m in lookalike_pat.finditer(text):
        warnings.append({
            "rule": "Brand Lookalike Domain",
            "description": (
                "The link contains a well-known brand name inside an unofficial domain. "
                "This is a phishing tactic — official sites use their exact brand domain "
                "(e.g. netflix.com, not netflix-secure-update.xyz)."
            ),
            "weight": 25,
            "excerpt": m.group(),
        })

    return warnings


def rule_excessive_caps(text: str) -> list[dict]:
    """Excessive use of capital letters (shouting / spam style)."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return []
    caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    if caps_ratio >= 0.40:
        m = re.search(r"\b[A-Z]{3,}(\s+[A-Z]{3,}){1,}\b", text)
        excerpt = m.group() if m else f"{int(caps_ratio * 100)}% uppercase"
        return [
            {
                "rule": "Excessive Capital Letters",
                "description": (
                    "Over 40% of the letters in this message are uppercase. "
                    "Spam and scam messages often shout in capitals to grab attention."
                ),
                "weight": 8,
                "excerpt": excerpt,
            }
        ]
    return []


def rule_excessive_punctuation(text: str) -> list[dict]:
    """Three or more consecutive ! or ? (spam style)."""
    matches = re.findall(r"[!?]{3,}", text)
    return [
        {
            "rule": "Excessive Punctuation",
            "description": (
                "Spam messages frequently use strings of exclamation or question marks "
                "to manufacture excitement or panic."
            ),
            "weight": 5,
            "excerpt": m,
        }
        for m in matches
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_RULES = [
    rule_urgency,
    rule_threats,
    rule_credential_harvesting,
    rule_prize_lottery,
    rule_payment_demand,
    rule_impersonation,
    rule_suspicious_links,
    rule_excessive_caps,
    rule_excessive_punctuation,
]


def run_all_rules(text: str) -> list[dict]:
    """Run every rule against *text* and return the combined flat list of warnings."""
    warnings = []
    for rule_fn in ALL_RULES:
        warnings.extend(rule_fn(text))
    return warnings
