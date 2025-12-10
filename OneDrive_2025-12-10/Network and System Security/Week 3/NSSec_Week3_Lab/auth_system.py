# auth_system.py
import bcrypt
import pyotp
from password_strength import password_strength

class UserAuth:
    def __init__(self):
        # simple in-memory "database"
        # username -> {"password_hash": bytes, "totp_secret": str}
        self.users = {}

    def register_user(self, username: str, password: str) -> None:
        """Register a new user with strong password and TOTP."""
        if username in self.users:
            raise ValueError("User already exists.")

        # 1) check password strength
        check = password_strength(password)
        if check["score"] < 4:
            raise ValueError(
                "Password too weak according to strength meter. "
                "Use longer length and more character types."
            )

        # 2) hash password with bcrypt (includes salt automatically)
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

        # 3) create TOTP secret for this user
        totp_secret = pyotp.random_base32()

        self.users[username] = {
            "password_hash": pw_hash,
            "totp_secret": totp_secret,
        }

        print(f"User '{username}' registered.")
        print("Store this TOTP secret in an authenticator app:")
        print(totp_secret)

    def authenticate(self, username: str, password: str, totp_code: str) -> bool:
        """Verify password and TOTP code."""
        user = self.users.get(username)
        if not user:
            print("Unknown user.")
            return False

        # verify password
        if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
            print("Invalid password.")
            return False

        # verify TOTP
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code):
            print("Invalid or expired TOTP code.")
            return False

        print("Authentication successful.")
        return True

if __name__ == "__main__":
    auth = UserAuth()

    print("=== Registration ===")
    uname = input("Choose a username: ")
    pw = input("Choose a strong password: ")

    try:
        auth.register_user(uname, pw)
    except ValueError as e:
        print("Registration failed:", e)
        exit(1)

    print("\nNow set up the TOTP secret from the console in an authenticator app.")
    input("Press Enter when ready to test login...")

    print("\n=== Login ===")
    pw_login = input("Password: ")
    code = input("TOTP code from your app: ")

    auth.authenticate(uname, pw_login, code)
