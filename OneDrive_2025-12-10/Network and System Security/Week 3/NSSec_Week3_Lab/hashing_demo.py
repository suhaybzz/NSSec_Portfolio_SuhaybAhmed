# hashing_demo.py
import hashlib
import bcrypt

def hash_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def hash_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_bcrypt(password: str, rounds: int = 12) -> bytes:
    salt = bcrypt.gensalt(rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt)

def verify_bcrypt(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)

if __name__ == "__main__":
    pw = input("Enter a password to hash: ")

    md5_hash = hash_md5(pw)
    sha_hash = hash_sha256(pw)
    bcrypt_hash = hash_bcrypt(pw)

    print("\nMD5:     ", md5_hash)
    print("SHA-256: ", sha_hash)
    print("bcrypt:  ", bcrypt_hash.decode())

    check = input("\nRe-enter password to verify with bcrypt: ")
    print("bcrypt verification:", verify_bcrypt(check, bcrypt_hash))

    print("\nNotice: MD5 and SHA-256 are very fast, which is bad for password storage.")
    print("bcrypt is intentionally slow and includes the salt inside the hash string.")
