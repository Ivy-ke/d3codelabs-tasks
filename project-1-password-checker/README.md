Password Strength Checker

This is a command-line tool that evaluates the strength of a password by checking its length, character variety, estimated entropy, and common weak patterns. Based on the analysis, the password is classified as Weak, Medium, or Strong.

This project was developed as Project 1 of the DecodeLabs Industrial Training Kit. It focuses on the fundamentals of defensive programming and introduces basic password security concepts before moving into hashing and encryption.

Why This Project Matters

Weak passwords remain one of the leading causes of security breaches. According to the Verizon 2025 Data Breach Investigations Report, stolen or weak credentials continue to be one of the most common ways attackers gain unauthorized access to systems.

This project was developed to demonstrate how basic password validation can help encourage stronger password practices and improve overall security awareness.

Features

The program performs several checks to determine password strength, including:

Enforcing a minimum password length of 8 characters
Checking for the presence of:
Uppercase letters
Lowercase letters
Numbers
Special characters
Estimating password entropy to determine how difficult it would be to guess
Detecting common weak passwords and predictable patterns such as:
password
admin
1234
Repeated characters
Displaying a final password strength rating of:
Weak
Medium
Strong
How to Run the Program
python3 password_strength_checker_decodelabs.py

The program prompts the user to enter a password for analysis.

To exit the program, type:

exit
Example Output
Enter a password to check: P@ssw0rdXyZ99!

==========================================
PASSWORD STRENGTH REPORT

Length              : 14 (minimum required: 8)
Meets min length    : Yes
Lowercase letters   : Yes
Uppercase letters   : Yes
Digits              : Yes
Symbols             : Yes
Estimated entropy   : 91.76 bits

VERDICT             : STRONG
How the Password Is Evaluated

The program considers several factors when calculating password strength:

Password length
Variety of character types used
Estimated entropy (measured in bits)
Presence of common or predictable password patterns

These checks provide a simple way of identifying passwords that are easier for attackers to guess or crack.

Requirements
Python 3.x
No external libraries or dependencies required
Skills Demonstrated

Through this project, I strengthened my understanding of:

-Python string handling
-Conditional statements and decision-making
-User input validation
-Password security best practices
-Password entropy concepts
-Identifying common weak password patterns
-Basic defensive programming principles
