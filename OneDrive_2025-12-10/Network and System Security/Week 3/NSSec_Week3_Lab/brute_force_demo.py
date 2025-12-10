# brute_force_demo.py
import hashlib
import time

COMMON_PASSWORDS = [
    "password", "123456", "123456789", "letmein",
    "qwerty", "football", "monkey", "dragon"
]

def hash_md5(pw: str) -> str:
    return hashlib.md5(pw.encode("utf-8")).hexdigest()

def hash_sha256(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def brute_force_dictionary(target_hash: str, algo: str = "md5") -> None:
    if algo not in {"md5", "sha256"}:
        raise ValueError("algo must be 'md5' or 'sha256'")

    print(f"Target hash: {target_hash}")
    print(f"Algorithm:   {algo}\n")

    start = time.time()
    for guess in COMMON_PASSWORDS:
        if algo == "md5":
            h = hash_md5(guess)
        else:
            h = hash_sha256(guess)

        print(f"Trying {guess:10s} -> {h}")
        if h == target_hash:
            duration = time.time() - start
            print(f"\nPassword cracked: {guess}")
            print(f"Time taken: {duration:.4f} seconds")
            return

    duration = time.time() - start
    print("\nPassword not found in this small dictionary.")
    print(f"Time spent searching: {duration:.4f} seconds")

if __name__ == "__main__":
    password = "password"   # simulate user password
    algo = "md5"

    target = hash_md5(password) if algo == "md5" else hash_sha256(password)
    brute_force_dictionary(target, algo=algo)

    print("\nIn real attacks the wordlist can contain millions of entries, and")
    print("fast hashes like MD5/SHA-256 allow billions of guesses per second.")
