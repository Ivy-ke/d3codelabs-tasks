"""
DecodeLabs Industrial Training Kit — Project 2
Basic Encryption & Decryption (Caesar Cipher)
================================================
Track: Cryptographic Logic (Junior Analyst)

Concept:
    This isn't about "cracking codes" — it's about Data Confidentiality.
    Data in transit can't be protected by walls (firewalls, physical
    security); it has to be protected by mathematical transformation.
    The Caesar cipher is the simplest example of that idea: shift every
    character by a fixed amount so the message is unreadable without
    the key, but perfectly recoverable with it.

Structure: IPO Model
    INPUT   -> plaintext string + shift key (n)
    PROCESS -> character-by-character shift, using ASCII math
    OUTPUT  -> ciphertext (encryption) or recovered plaintext (decryption)

Key Requirements (from brief):
    1. Encrypt user text using a basic logic (Caesar cipher)
    2. Decrypt the encrypted text
    3. Display both encrypted and decrypted output

Key Skills demonstrated:
    - Encryption concepts (symmetric cipher: same key locks and unlocks)
    - Logic building (modular arithmetic to "wrap" the alphabet)
    - Data protection basics

Core math:
    Encrypt: E(x) = (x + n) % 26
    Decrypt: D(x) = (x - n) % 26
    where x = letter's position in the alphabet (A=0 ... Z=25), n = shift key

Known limitation (by design, not a bug):
    A Caesar cipher only has 25 possible keys, and it preserves the
    frequency pattern of the original language (e.g. 'E' is still the
    most common letter after shifting). That makes it trivially breakable
    by brute force or frequency analysis — it's a lockbox, not a vault.
    This project is about the fundamentals of the encrypt/decrypt cycle,
    not production-grade security (that comes with AES, in later work).
"""


ALPHABET_SIZE = 26



def shift_character(char: str, shift: int) -> str:
    """
    Shift a single character by `shift` positions in the alphabet.
    Non-letter characters (spaces, punctuation, digits) are returned
    unchanged — this is the "edge case handling" the brief calls for.
    """
    if char.isupper():
        base = ord('A')
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    elif char.islower():
        base = ord('a')
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    else:
        # Spaces, punctuation, digits, symbols: pass through untouched
        return char



def encrypt(plaintext: str, shift: int) -> str:
    """
    INPUT:   plaintext string, shift key
    PROCESS: shift every letter forward by `shift`
    OUTPUT:  ciphertext string
    """
    return "".join(shift_character(char, shift) for char in plaintext)


def decrypt(ciphertext: str, shift: int) -> str:
    """
    INPUT:   ciphertext string, shift key
    PROCESS: shift every letter backward by `shift` (reverse of encrypt)
    OUTPUT:  recovered plaintext string

    Symmetric encryption: the same key that locks the message also
    unlocks it — decryption is just encryption run with a negative shift.
    """
    return encrypt(ciphertext, -shift)


# ---------------------------------------------------------------------------
# Presentation layer
# ---------------------------------------------------------------------------

def get_shift_key() -> int:
    """Prompt for a shift key, validating it's an integer."""
    while True:
        raw = input("Enter shift key (1-25 recommended): ").strip()
        try:
            return int(raw)
        except ValueError:
            print("Please enter a whole number.\n")


def main():
    print("DecodeLabs Project 2 - Caesar Cipher Encryption & Decryption")
    print("(Type 'exit' to quit)\n")

    while True:
        text = input("Enter text to encrypt: ")
        if text.lower() == "exit":
            print("Session ended.")
            break
        if not text:
            print("Please enter a non-empty message.\n")
            continue

        shift = get_shift_key()

        ciphertext = encrypt(text, shift)
        recovered = decrypt(ciphertext, shift)

        print("\n" + "=" * 48)
        print(" CAESAR CIPHER REPORT")
        print("=" * 48)
        print(f"Shift key            : {shift}")
        print(f"Original text        : {text}")
        print(f"Encrypted (cipher)   : {ciphertext}")
        print(f"Decrypted (recovered): {recovered}")
        print(f"Round-trip verified  : {'Yes' if recovered == text else 'NO - logic error'}")
        print("=" * 48 + "\n")


if __name__ == "__main__":
    main()
