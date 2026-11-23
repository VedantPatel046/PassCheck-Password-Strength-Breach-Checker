# PassCheck (Python edition)

A small command-line password strength and breach checker for learning Python. It uses only the Python standard library; no packages need to be installed.

## Run it

Open a terminal in this folder and run:

```bash
python3 passcheck.py
```

On Windows, `py passcheck.py` may be the command to use. The program asks for a password using Python's `getpass` function, which hides the typed characters in a normal terminal. It then shows a basic strength estimate and asks whether to check known breach data. Strength checking works offline; the breach lookup needs an internet connection.

## Privacy

The password and complete hash are not sent or written to a file. The program calculates a SHA-1 hash locally, sends only the first five hash characters to the Have I Been Pwned Pwned Passwords range API, and compares the returned suffixes locally. The five-character prefix is still sent to that service, so this is a privacy-preserving lookup, not a zero-network-disclosure claim. Use a made-up password for practice, not one you use for an account.

The strength score and common-password list are intentionally simple for learning. They are not a guarantee of security or a replacement for a password manager.

## macOS certificate error

If the breach lookup reports `CERTIFICATE_VERIFY_FAILED`, Python is missing or cannot find its trusted HTTPS root certificates. Do not disable certificate verification. For Python installed from python.org, open **Applications → Python 3.14 → Install Certificates.command**, let the Terminal window finish, and run the program again. Use the folder matching your installed Python version. The official Python macOS guide describes this certificate setup step.

## Resume description

**PassCheck — Python Password Strength & Breach Checker:** Built a command-line security tool with Python's standard library, hidden password input, local strength checks, and a k-anonymity breach lookup that sends only a partial SHA-1 hash prefix.

## Main Python ideas used

- Functions to separate the strength check, breach lookup, and program flow.
- A set to check a small list of common passwords.
- Regular expressions to look for character groups and repeated characters.
- `hashlib` to calculate a SHA-1 hash locally.
- `getpass` to hide the password as it is typed.
- `urllib` to make an HTTPS request without installing an extra library.
- `try` and `except` to show a helpful message if the network lookup fails.
