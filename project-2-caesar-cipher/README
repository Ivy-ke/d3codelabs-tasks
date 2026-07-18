Caesar Cipher — Encryption & Decryption Tool

This is a command-line application that encrypts and decrypts text using the Caesar cipher, one of the earliest and simplest encryption techniques. Although it is not secure enough for modern applications, it provides a good introduction to the basic concepts of cryptography.

This project was developed as Project 2 of the DecodeLabs Industrial Training Kit. It focuses on the fundamentals of data confidentiality and builds on the programming concepts learned in Project 1 by introducing basic encryption techniques.

What This Project Demonstrates

Through this project, I learned and demonstrated:

The basic concept of symmetric encryption, where the same key is used for both encryption and decryption.
Character-by-character string manipulation using ASCII values.
The use of modular arithmetic to correctly wrap letters around the alphabet.
Applying the Input → Process → Output (IPO) programming model to build a complete application.
Background: What Is a Caesar Cipher?

The Caesar cipher is one of the oldest known encryption methods. It is believed to have been used by Julius Caesar to protect military communications by shifting each letter in a message by a fixed number of positions in the alphabet.

For example, using a shift of 3:

A becomes D
B becomes E
X becomes A
Y becomes B
Z becomes C

This is known as a substitution cipher because every letter is replaced with another letter based on a fixed shift value (the key).

Although the Caesar cipher is no longer considered secure, it is still widely taught because it introduces important cryptography concepts such as:

Plaintext
Ciphertext
Encryption
Decryption
Encryption keys
How the Program Works
Encryption Formula
E(x) = (x + n) mod 26
Decryption Formula
D(x) = (x - n) mod 26

Where:

x represents the letter's position in the alphabet (A = 0, B = 1 ... Z = 25).
n is the shift key chosen by the user.
mod 26 ensures that letters wrap around to the beginning of the alphabet after Z.
Example

Using a shift value of 3:

Letter Y has position 24
24 + 3 = 27
27 mod 26 = 1
Position 1 corresponds to B

Therefore, Y is encrypted as B.

Implementation in Python

The program uses Python's built-in ord() and chr() functions to convert characters to ASCII values and back again.

cipher_char = chr((ord(char) - 65 + shift) % 26 + 65)

In simple terms, the program:

Converts the letter into its ASCII value.
Converts it into a position between 0 and 25.
Adds the shift value.
Uses modulo (% 26) to wrap around the alphabet if needed.
Converts the result back into a readable letter.
How Decryption Works

The Caesar cipher uses symmetric encryption, meaning the same key is used for both encrypting and decrypting a message.

To decrypt the text, the program simply shifts the letters in the opposite direction.

D(x) = (x - n) mod 26

This reverses the encryption process and restores the original message.

How to Run the Program
python3 caesar_cipher_decodelabs.py

The program prompts the user to enter:

The text to encrypt.
A shift key (typically between 1 and 25).

After processing, it displays:

The original message
The encrypted ciphertext
The decrypted message

This allows the user to verify that the encryption and decryption process works correctly.

Example Output
Enter text to encrypt: Attack at Dawn
Enter shift key (1-25 recommended): 7

CAESAR CIPHER REPORT

Shift key            : 7
Original text        : Attack at Dawn
Encrypted (cipher)   : Haahjr ha Khdu
Decrypted (recovered): Attack at Dawn
Round-trip verified  : Yes
Features Implemented

The program also handles several common situations correctly:

Case preservation – uppercase and lowercase letters remain unchanged after encryption.
Non-letter characters – spaces, numbers, and punctuation are left unchanged.
Alphabet wrap-around – letters shifted beyond Z correctly continue from A using modular arithmetic.
Security Note

This project was created for educational purposes to understand the fundamentals of encryption rather than to provide secure communication.

The Caesar cipher has several limitations:

Small key space – there are only 25 possible shift values, making it easy to crack using a brute-force attack.
Frequency analysis – the frequency of letters remains the same after shifting, allowing attackers to estimate the key by analyzing letter patterns.

These weaknesses explain why stronger encryption algorithms such as AES are used today. Modern encryption methods use much larger key spaces and more advanced mathematical techniques to provide stronger security.

Requirements
Python 3.x
No external libraries or dependencies required.
Skills Demonstrated

This project helped me strengthen my understanding of:

Basic cryptography concepts
Symmetric encryption and decryption
Python programming
ASCII character manipulation
Modular arithmetic
Algorithm design and problem-solving
Input–Process–Output (IPO) programming principles

.
