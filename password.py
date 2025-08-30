import re
import hashlib
import requests

def check_strength(password: str) -> str:
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password too short (<8 chars).")

    # Uppercase, lowercase, digits, symbols
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Add uppercase letters.")
    
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("Add lowercase letters.")
    
    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("Add numbers.")
    
    if re.search(r"[@$!%*?&^#()_+=\-]", password): score += 1
    else: feedback.append("Add special characters.")

    # Score evaluation
    if score >= 6:
        verdict = "✅ Strong"
    elif score >= 4:
        verdict = "🟡 Medium"
    else:
        verdict = "❌ Weak"

    return verdict, feedback


def check_pwned(password: str) -> int:
    # SHA1 hash
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    
    # Query HIBP
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    
    if res.status_code != 200:
        return -1  # API error
    
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)  # found in leaks
    return 0


if __name__ == "__main__":
    pwd = input("Enter a password to test: ")

    verdict, feedback = check_strength(pwd)
    print(f"\nStrength: {verdict}")
    if feedback:
        print("Suggestions:")
        for f in feedback:
            print(" -", f)

    # Check leaks
    count = check_pwned(pwd)
    if count > 0:
        print(f"⚠️ This password has appeared {count} times in data breaches!")
    elif count == 0:
        print("✅ This password was NOT found in known breaches.")
    else:
        print("⚠️ Could not check breach database (API error).")
