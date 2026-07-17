Track: defense logic

    Why this matters (per Verizon DBIR):
    
  A large majority of hacking-related attacks use  weak or stolen passwords. 
  Before defending any large networks, an analyst MUST first master the fundamentals:
   1.string validation, entropy which measures unpredictability ,(how hard something it is to guess)and clean conditional logic.


   Structure: IPO Model
    INPUT   -> raw password string
    PROCESS -> validation + scoring (O(n), single linear scan)
    OUTPUT  -> risk classification: WEAK / MEDIUM / STRONG

Key Requirements 
    1. Check password length            -> hard fail if < 8 char
    2. Check numbers, symbols, uppercase -> mandatory characters
    3. Display password strength result  -> clear verdict + reasoning

code...//
   import re
import math
import string

def has_lowercase(password: str) -> bool:
    return any(char.islower() for char in password)


def has_uppercase(password: str) -> bool:
    return any(char.isupper() for char in password)


def has_digit(password: str) -> bool:
    return any(char.isdigit() for char in password)


def has_symbol(password: str) -> bool:
    return any(char in string.punctuation for char in password)


# ---------------------------------------------------------------------------
# PROCESS: Length policy
# ---------------------------------------------------------------------------

MIN_LENGTH = 8  # Per policy: "< 8 chars = immediate fail"


def meets_minimum_length(password: str) -> bool:
    return len(password) >= MIN_LENGTH


def length_score(password: str) -> int:
    """Extra scoring tiers above the hard minimum, for finer-grained results."""
    length = len(password)
    if length < MIN_LENGTH:
        return 0
    elif length < 12:
        return 1
    elif length < 16:
        return 2
    return 3


# ---------------------------------------------------------------------------
# PROCESS: Entropy estimation
# ---------------------------------------------------------------------------
# Simplified academic model: entropy (bits) = length * log2(pool size).
# Pool size grows with each character class present. This mirrors the
# "search space" idea from the brief (charset size directly drives how
# hard a password is to brute-force) without needing full Unicode support.

def estimate_entropy(password: str) -> float:
    pool = 0
    if has_lowercase(password):
        pool += 26
    if has_uppercase(password):
        pool += 26
    if has_digit(password):
        pool += 10
    if has_symbol(password):
        pool += len(string.punctuation)

    if pool == 0 or len(password) == 0:
        return 0.0

    return len(password) * math.log2(pool)


# ---------------------------------------------------------------------------
# PROCESS: Common weak-pattern detection
# ---------------------------------------------------------------------------
# Bonus per the brief's conclusion slide: "adding a check for common
# 'leaked' passwords" is explicitly called out as a good extension.
# This is a small illustrative list, not a full breach-corpus lookup.

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "qwerty", "letmein", "admin",
    "welcome", "iloveyou", "111111", "abc123",
}


def find_common_pattern_issues(password: str) -> list:
    issues = []
    lowered = password.lower()

    for weak in COMMON_WEAK_PASSWORDS:
        if weak in lowered:
            issues.append(f"Contains a widely leaked/common term: '{weak}'")

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated characters (e.g. 'aaa')")

    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", lowered):
        issues.append("Contains a sequential pattern (e.g. '1234', 'abcd')")

    return issues



def evaluate_password(password: str) -> dict:
    """
    INPUT:   password (str)
    PROCESS: length policy + character classes + entropy + pattern checks
    OUTPUT:  dict with full breakdown and a WEAK / MEDIUM / STRONG verdict
    """
    passes_min_length = meets_minimum_length(password)

    classes = {
        "lowercase": has_lowercase(password),
        "uppercase": has_uppercase(password),
        "digits": has_digit(password),
        "symbols": has_symbol(password),
    }
    class_score = sum(classes.values())          # 0-4
    len_score = length_score(password)           # 0-3
    entropy = estimate_entropy(password)
    issues = find_common_pattern_issues(password)

    # Hard fail: policy says <8 chars is an immediate fail, regardless
    # of anything else.
    if not passes_min_length:
        verdict = "WEAK"
    else:
        total = len_score + class_score - len(issues)
        total = max(0, total)

        if total <= 2 or entropy < 28:
            verdict = "WEAK"
        elif total <= 5 or entropy < 50:
            verdict = "MEDIUM"
        else:
            verdict = "STRONG"

    return {
        "length": len(password),
        "passes_min_length": passes_min_length,
        "character_classes": classes,
        "entropy_bits": round(entropy, 2),
        "pattern_issues": issues,
        "verdict": verdict,
    }



def print_report(password: str) -> None:
    result = evaluate_password(password)

    print("\n" + "=" * 48)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 48)
    print(f"Length              : {result['length']} (minimum required: {MIN_LENGTH})")
    print(f"Meets min length    : {'Yes' if result['passes_min_length'] else 'NO - hard fail'}")
    print(f"Lowercase letters   : {'Yes' if result['character_classes']['lowercase'] else 'No'}")
    print(f"Uppercase letters   : {'Yes' if result['character_classes']['uppercase'] else 'No'}")
    print(f"Digits              : {'Yes' if result['character_classes']['digits'] else 'No'}")
    print(f"Symbols             : {'Yes' if result['character_classes']['symbols'] else 'No'}")
    print(f"Estimated entropy   : {result['entropy_bits']} bits")

    if result["pattern_issues"]:
        print("\nWarnings:")
        for issue in result["pattern_issues"]:
            print(f"  - {issue}")

    print(f"\nVERDICT             : {result['verdict']}")
    print("=" * 48 + "\n")


def main():
    print("DecodeLabs Project 1 - Password Strength Checker")
    print("(Type 'exit' to quit)\n")

    while True:
        password = input("Enter a password to check: ")
        if password.lower() == "exit":
            print("Session ended.")
            break
        if not password:
            print("Please enter a non-empty password.\n")
            continue

        print_report(password)


if __name__ == "__main__":
    main()

