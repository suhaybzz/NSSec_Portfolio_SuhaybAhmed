# password_strength.py
import math
import string

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein",
    "pass123", "password1", "admin", "iloveyou"
}

def estimate_entropy(password: str) -> float:
    """Approximate entropy = length * log2(pool_size)."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    return len(password) * math.log2(pool_size or 1)

def password_strength(password: str) -> dict:
    score = 0
    feedback = []

    # length checks
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1

    # character variety
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Include lowercase letters.")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Include uppercase letters.")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Include digits.")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Include special characters (punctuation).")

    # common password check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("This password is very common and unsafe.")
        score = max(score - 2, 0)

    entropy = estimate_entropy(password)

    return {
        "password": password,
        "score": score,
        "entropy_bits": entropy,
        "feedback": feedback
    }

if __name__ == "__main__":
    test_pw = input("Enter a password to analyse: ")
    result = password_strength(test_pw)

    print(f"\nPassword: {result['password']}")
    print(f"Score (0–6): {result['score']}")
    print(f"Estimated entropy: {result['entropy_bits']:.2f} bits")

    if result["feedback"]:
        print("Suggestions:")
        for line in result["feedback"]:
            print(" -", line)
    else:
        print("Looks strong based on this simple checker.")

    print("\nNote: this checker cannot see dictionary patterns or phrases.")
