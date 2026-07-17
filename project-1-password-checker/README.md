# Password Strength Checker

A command-line tool that evaluates whether a password is **Weak**, **Medium**, or **Strong** based on length, character variety, estimated entropy, and common weak-pattern detection.

Built as Project 1 of the DecodeLabs Industrial Training Kit — the defensive-logic foundation before moving into hashing and encryption.

## Why

Per Verizon's 2025 Data Breach Investigations Report, stolen or weak credentials remain the top initial access vector into organizations, factoring into **22% of all breaches** — and **88% of basic web application attacks** specifically involve stolen credentials. Strong password validation is a first line of defense against this.

## Features

- Enforces an 8-character minimum (hard fail below this, per policy)
- Checks for uppercase, lowercase, digits, and symbols
- Estimates entropy (bits) based on character pool size
- Flags common leaked/weak patterns (e.g. `password`, `admin`, `1234`, repeated characters)
- Clear WEAK / MEDIUM / STRONG verdict with full breakdown

## Usage

```bash
python3 password_strength_checker_decodelabs.py
```

Type a password when prompted to see its strength report. Type `exit` to quit.

## Example
Enter a password to check: P@ssw0rdXyZ99!
================================================
PASSWORD STRENGTH REPORT
Length              : 14 (minimum required: 8)
Meets min length    : Yes
Lowercase letters   : Yes
Uppercase letters   : Yes
Digits              : Yes
Symbols             : Yes
Estimated entropy   : 91.76 bits

VERDICT             : STRONG
## Requirements

Python 3.x — no external dependencies.

## Skills Demonstrated

String handling, conditional logic, and foundational security concepts (entropy, common-pattern detection).
