"""PassCheck: a beginner-friendly password strength and breach checker."""

import hashlib
import re
import ssl
import urllib.error
import urllib.request
from getpass import getpass


# This is a short teaching list, not a complete list of weak passwords.
COMMON_PASSWORDS = {
    "123456", "12345678", "123456789", "password", "password1",
    "qwerty", "qwerty123", "letmein", "welcome", "admin", "iloveyou",
    "abc123",
}


def check_strength(password):
    """Return a score from 0 to 4 and the three recommendation results."""
    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_number = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))
    character_types = sum((has_lowercase, has_uppercase, has_number, has_symbol))

    is_common = password.lower() in COMMON_PASSWORDS
    has_repeated_run = bool(re.search(r"(.)\1{3,}", password))
    recommendations = {
        "At least 12 characters": len(password) >= 12,
        "Mix of character types": character_types >= 3,
        "Avoid common/repeated patterns": not is_common and not has_repeated_run,
    }

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if character_types >= 2:
        score += 1
    if character_types >= 3:
        score += 1

    if is_common or has_repeated_run:
        score = min(score, 1)
    if len(password) < 5:
        score = 0

    return min(score, 4), recommendations


def check_breach(password):
    """Look up the password using the Pwned Passwords range API.

    The full password and full hash stay on this computer. The request sends
    only the first five characters of the locally calculated SHA-1 hash.
    """
    password_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = password_hash[:5]
    suffix = password_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    request = urllib.request.Request(
        url,
        headers={
            "Add-Padding": "true",
            "User-Agent": "PassCheck-Beginner-Project",
        },
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        response_text = response.read().decode("utf-8")

    for line in response_text.splitlines():
        returned_suffix, count = line.split(":", maxsplit=1)
        if returned_suffix.strip().upper() == suffix:
            return int(count.strip())
    return 0


def main():
    """Ask for one password, show its score, then offer a breach lookup."""
    print("\nPassCheck - Password Strength & Breach Checker")
    print("Your password is hidden while you type. It is not saved.\n")

    password = getpass("Enter a password to check: ")
    if not password:
        print("No password entered. Goodbye.")
        return

    score, recommendations = check_strength(password)
    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    print(f"\nEstimated strength: {labels[score]}")
    print("Recommendations:")
    for recommendation, passed in recommendations.items():
        mark = "[x]" if passed else "[ ]"
        print(f"  {mark} {recommendation}")

    answer = input("\nCheck known breach data? (y/n): ").strip().lower()
    if answer != "y":
        print("Breach lookup skipped. Choose unique passwords for your accounts.")
        return

    print("Checking securely...")
    try:
        count = check_breach(password)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLCertVerificationError):
            print("Python could not find trusted HTTPS certificates on this Mac.")
            print('Open Applications > Python 3.14 > "Install Certificates.command",')
            print("let it finish, then run this program again.")
            print("If your Python version is different, open its matching Python folder.")
        else:
            print("Could not reach the breach lookup service. Check your connection and try again.")
        return
    except (TimeoutError, UnicodeDecodeError):
        print("The breach lookup timed out or returned unreadable data. Please try again.")
        return

    if count:
        print(f"This password appears {count:,} times in known breach data.")
        print("Choose a different password and do not reuse it.")
    else:
        print("No match found in the known breach data checked.")
        print("This does not guarantee the password is safe; use a unique password.")


if __name__ == "__main__":
    main()
