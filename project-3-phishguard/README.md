PhishGuard — Phishing Awareness Analyzer

PhishGuard is a command-line tool that analyzes an email or message for common phishing indicators such as suspicious keywords, lookalike URLs, and sender/domain mismatches. Based on what it finds, the tool generates a risk score, classifies the message, and provides a simple explanation of each red flag detected.

This project was developed as Project 3 of the DecodeLabs Industrial Training Kit. It focuses on the detection phase of cybersecurity and builds on the concepts learned in Project 1 (basic programming logic) and Project 2 (cryptography) by applying them to phishing detection.

Why This Matters

One of the biggest cybersecurity risks today is phishing. Even with strong security systems in place, a single click on a malicious email can compromise an organization. This project was designed to help users and beginner security analysts understand how phishing emails are identified by clearly explaining why certain elements are considered suspicious instead of simply labeling them as unsafe.

What the Tool Checks
1. Keyword and Phrase Detection

The tool scans the email or message for words and phrases that are commonly used in phishing attacks. These include urgent language such as "immediately" or "act now", fear-based phrases like "account suspended" or "unusual activity", and reward-based messages such as "claim now" or "winner".

Instead of only flagging these words, the tool also explains the type of social engineering technique being used, such as:

Urgency
Authority
Fear
Curiosity
Greed
2. URL Analysis

If the message contains links, the tool analyzes each URL for signs that it may be malicious. It checks for:

Letter and number substitutions (for example, amaz0n.com)
Domains containing excessive hyphens, such as secure-bank-login-check.com
Links that use a raw IP address instead of a domain name
Trusted brand names appearing inside unrelated domains

These checks help identify links that may have been designed to imitate legitimate websites.

3. Sender Domain Verification

When both a display name (such as IT Support) and an email address are provided, the tool checks whether the sender's domain matches what would normally be expected from that organization.

For example, if a message claims to come from a company but uses a personal Gmail or Yahoo email address, the tool flags it as suspicious.

Risk Scoring

Each indicator contributes to an overall phishing risk score.

Finding	Points
Each suspicious keyword or phrase	+10
Each URL detected	+15
Each suspicious URL characteristic	+10
Sender/domain mismatch	+25

Based on the total score, the message is classified as follows:

Score	Classification	Recommended Action
0–24	Safe	No major phishing indicators detected.
25–59	Suspicious	Verify the message through another trusted communication channel before taking any action.
60+	Malicious	Treat the message as a phishing attempt and report or block it immediately.
This scoring system provides a simple way to estimate the likelihood that a message is a phishing attempt while helping users understand which indicators contributed to the final result.
