"""
DecodeLabs Industrial Training Kit — Project 3
PhishGuard: Phishing Awareness Analysis Tool
================================================
Track: Threat Detection (Junior Analyst)

Concept:
    The modern security perimeter isn't the network firewall -- it's
    the user. This tool doesn't block anything; it analyzes a message
    the way a trained analyst would during triage: looking for red
    flags, scoring the risk, and recommending an action.

Structure: IPO Model
    INPUT   -> raw email/message text (+ optional sender address)
    PROCESS -> keyword detection, URL extraction, domain-mismatch and
               lookalike-domain checks, urgency/authority pattern checks
    OUTPUT  -> risk score, itemized findings, and a triage classification
               (Safe / Suspicious / Malicious) with a recommended action

Key Requirements (from brief):
    1. Identify suspicious links or keywords
    2. List red flags found in phishing messages
    3. Explain why the message is unsafe

Key Skills demonstrated:
    - Threat analysis
    - Awareness of common cyber attack patterns
    - Security-minded conditional logic

Known limitation (by design, not a bug):
    This is a rule-based / keyword-based analyzer, not a machine-learning
    classifier. It's built to demonstrate the analyst's *reasoning process*
    (what red flags matter and why), not to serve as a production email
    filter. Real-world tools combine this kind of logic with SPF/DKIM/DMARC
    header verification, domain reputation lookups, and often ML models
    trained on large phishing/legitimate email datasets.
"""

import re
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# Reference data: what we're looking for, and why it matters
# ---------------------------------------------------------------------------
# Each keyword is mapped to *why* it's a red flag, tying back to the
# psychological triggers named in the brief: Authority, Urgency,
# Curiosity, Fear/Greed.

PHISHING_KEYWORDS = {
    "urgent": "Urgency trigger — creates time pressure to bypass careful thinking",
    "immediately": "Urgency trigger — pushes the reader to act before verifying",
    "verify your account": "Credential harvesting — asks you to 'confirm' login details",
    "verify your identity": "Credential harvesting attempt",
    "suspended": "Fear trigger — threatens loss of access to force quick action",
    "click here": "Vague link text — hides the real destination from the reader",
    "claim now": "Greed trigger — dangles a reward to lower your guard",
    "winner": "Greed trigger — classic prize-scam bait",
    "confirm your password": "Direct credential harvesting attempt",
    "security alert": "Authority/fear trigger — mimics legitimate IT security messaging",
    "wire transfer": "Common Business Email Compromise (BEC) request pattern",
    "gift card": "Common payment method requested in scams (hard to trace/reverse)",
    "act now": "Urgency trigger",
    "unusual activity": "Fear trigger — false alarm designed to prompt a rushed click",
}

# A small list of brands commonly impersonated, used for the domain
# mismatch check below (not exhaustive — illustrative for this project).
COMMONLY_IMPERSONATED_BRANDS = [
    "paypal", "microsoft", "google", "amazon", "apple", "bank", "netflix",
]


# ---------------------------------------------------------------------------
# PROCESS: URL extraction and analysis
# ---------------------------------------------------------------------------

def extract_urls(message: str) -> list:
    """Find all http(s) URLs in the message body."""
    return re.findall(r'https?://[^\s<>"\')]+', message)


def analyze_url(url: str) -> list:
    """
    Look for common lookalike-domain tactics named in the brief:
    typosquatting-style digit substitution, excessive hyphens/subdomains
    used to bury the real root domain, and raw IP addresses instead of
    a domain name.
    """
    issues = []

    # Digit-for-letter substitution (e.g. amaz0n.com, paypa1.com)
    if re.search(r'[0-9]', url.split('/')[2] if '//' in url else url):
        domain_part = url.split('/')[2] if '//' in url else url
        if re.search(r'[a-zA-Z][0-9][a-zA-Z]|[0-9][a-zA-Z][0-9]', domain_part):
            issues.append(
                f"Possible typosquatting (letter/digit substitution) in: {domain_part}"
            )

    # Excessive hyphens: often used to bury a real brand name in a fake domain
    domain_part = url.split('/')[2] if '//' in url else url
    if domain_part.count('-') >= 2:
        issues.append(
            f"Domain uses multiple hyphens, a common lookalike-domain tactic: {domain_part}"
        )

    # Raw IP address instead of a domain name
    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain_part.split(':')[0]):
        issues.append(f"URL uses a raw IP address instead of a domain: {domain_part}")

    # Brand name mentioned inside a domain that isn't that brand's real domain
    for brand in COMMONLY_IMPERSONATED_BRANDS:
        if brand in domain_part.lower() and not domain_part.lower().startswith(brand + "."):
            issues.append(
                f"Brand name '{brand}' appears inside an unrelated domain: {domain_part}"
            )

    return issues


# ---------------------------------------------------------------------------
# PROCESS: Keyword / phrase detection
# ---------------------------------------------------------------------------

def detect_keywords(message: str) -> list:
    """
    Match whole phrases/words only (word-boundary aware), so 'login' inside
    a URL like 'secure-bank-login-check.com' doesn't get miscounted as a
    keyword hit in the message body. Matching the *body text* separately
    from the *URL text* keeps the scoring honest.
    """
    text_only = message
    for url in extract_urls(message):
        text_only = text_only.replace(url, "")  # strip URLs before keyword scan

    text_lower = text_only.lower()
    found = []
    for phrase, reason in PHISHING_KEYWORDS.items():
        pattern = r'\b' + re.escape(phrase) + r'\b'
        if re.search(pattern, text_lower):
            found.append((phrase, reason))
    return found


# ---------------------------------------------------------------------------
# PROCESS: Sender domain mismatch check
# ---------------------------------------------------------------------------

def check_sender_mismatch(display_name: str, sender_email: str) -> list:
    """
    Classic 'Red Flag 1' from the brief: the display name claims to be
    one thing (e.g. 'IT Support') while the actual email domain is
    something unrelated (e.g. a free Gmail address).
    """
    issues = []
    if not sender_email or "@" not in sender_email:
        return issues

    domain = sender_email.split("@")[-1].lower()
    free_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

    corporate_signals = ["support", "security", "admin", "it", "hr", "helpdesk", "bank"]
    name_lower = display_name.lower()

    if domain in free_providers and any(signal in name_lower for signal in corporate_signals):
        issues.append(
            f"Sender claims to be '{display_name}' but sends from a free "
            f"email provider ({domain}) — legitimate organizations don't "
            f"use free consumer email for official communication"
        )

    return issues


# ---------------------------------------------------------------------------
# OUTPUT: Combine everything into a risk score + classification
# ---------------------------------------------------------------------------

def analyze_message(message: str, display_name: str = "", sender_email: str = "") -> dict:
    """
    INPUT:   message body, optional sender display name + email
    PROCESS: keyword scan, URL analysis, sender mismatch check
    OUTPUT:  dict with score, findings, classification, and recommended action
    """
    findings = []
    score = 0

    # Keyword analysis (10 points per distinct keyword found)
    keywords = detect_keywords(message)
    for phrase, reason in keywords:
        score += 10
        findings.append(f"Keyword detected: '{phrase}' — {reason}")

    # URL analysis (15 points per URL present, plus extra per red flag found)
    urls = extract_urls(message)
    for url in urls:
        score += 15
        findings.append(f"URL found in message: {url}")
        url_issues = analyze_url(url)
        for issue in url_issues:
            score += 10
            findings.append(f"  -> {issue}")

    # Sender mismatch check
    sender_issues = check_sender_mismatch(display_name, sender_email)
    for issue in sender_issues:
        score += 25
        findings.append(f"Sender red flag: {issue}")

    # Classification per the brief's Safe / Suspicious / Malicious triage tree
    if score >= 60:
        classification = "MALICIOUS"
        action = "Block domain & escalate to security team"
    elif score >= 25:
        classification = "SUSPICIOUS"
        action = "Warn user — do not click, verify via a separate channel"
    else:
        classification = "SAFE"
        action = "Close — no strong indicators found"

    return {
        "score": score,
        "findings": findings,
        "classification": classification,
        "recommended_action": action,
    }


# ---------------------------------------------------------------------------
# Presentation layer
# ---------------------------------------------------------------------------

def print_report(result: dict) -> None:
    print("\n" + "=" * 60)
    print(" PHISHGUARD ANALYSIS REPORT")
    print("=" * 60)
    print(f"Risk score          : {result['score']}")
    print(f"Classification      : {result['classification']}")
    print(f"Recommended action  : {result['recommended_action']}")

    if result["findings"]:
        print("\nFindings:")
        for item in result["findings"]:
            print(f"  - {item}")
    else:
        print("\nNo red flags detected.")

    print("=" * 60 + "\n")


def save_report(result: dict, message: str) -> str:
    """Save the report to disk. Creates the reports/ folder if it's missing --
    this is the fix for the original script's crash-on-first-run bug."""
    os.makedirs("reports", exist_ok=True)

    report_text = (
        f"PhishGuard Security Analysis Report\n"
        f"Date: {datetime.now()}\n\n"
        f"Original message:\n{message}\n\n"
        f"Risk score: {result['score']}\n"
        f"Classification: {result['classification']}\n"
        f"Recommended action: {result['recommended_action']}\n\n"
        f"Findings:\n"
    )
    for item in result["findings"]:
        report_text += f"- {item}\n"

    filepath = os.path.join("reports", "analysis_report.txt")
    with open(filepath, "w") as f:
        f.write(report_text)

    return filepath


def read_multiline_message() -> str:
    """
    input() only reads a single line, which truncates a pasted multi-line
    email at the first line break. This reads line-by-line until the user
    types a lone 'END' on its own line, so full messages paste correctly.
    """
    print("\nPaste the email/message text below.")
    print("When finished, type END on its own line and press Enter:\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def main():
    print("=" * 60)
    print(" PhishGuard — Phishing Awareness Analyzer")
    print(" DecodeLabs Project 3: Threat Detection")
    print("=" * 60)

    message = read_multiline_message()
    if not message.strip():
        print("No message entered. Exiting.")
        return

    display_name = input("\nSender display name (optional, press Enter to skip): ")
    sender_email = input("Sender email address (optional, press Enter to skip): ")

    result = analyze_message(message, display_name, sender_email)
    print_report(result)

    filepath = save_report(result, message)
    print(f"Report saved to: {filepath}")


if __name__ == "__main__":
    main()
