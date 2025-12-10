# salt_pepper_demo.py
import os
import hashlib

SECRET_PEPPER = "CHANGE_THIS_SECRET_PEPPER"  # store in config/env in real systems

def sha256_no_salt(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def sha256_with_salt(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()

def sha256_with_salt_and_pepper(password: str, salt: bytes) -> str:
    return hashlib.sha256(
        salt + password.encode("utf-8") + SECRET_PEPPER.encode("utf-8")
    ).hexdigest()

if __name__ == "__main__":
    pw = "user123password"
    print("Password used:", pw)

    # 1) no salt
    h1 = sha256_no_salt(pw)
    h2 = sha256_no_salt(pw)
    print("\nNo salt:")
    print("hash 1:", h1)
    print("hash 2:", h2)
    print("Same hash for same password -> rainbow tables are effective.")

    # 2) with salt
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)
    hs1 = sha256_with_salt(pw, salt1)
    hs2 = sha256_with_salt(pw, salt2)
    print("\nWith unique random salts:")
    print("salt 1:", salt1.hex(), "| hash:", hs1)
    print("salt 2:", salt2.hex(), "| hash:", hs2)
    print("Different salts give different hashes even for same password.")

    # 3) with salt and pepper
    hp = sha256_with_salt_and_pepper(pw, salt1)
    print("\nWith salt + secret pepper:")
    print("salt:", salt1.hex())
    print("hash with pepper:", hp)
    print("Attacker must now know both salt (from DB) and hidden pepper (from app).")
