# totp_demo.py
import time
import pyotp
import qrcode

def create_totp_secret(account_name: str, issuer: str = "NSSecDemo") -> str:
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name,
        issuer_name=issuer
    )

    img = qrcode.make(uri)
    img.save("totp_qr.png")

    print("TOTP secret:", secret)
    print("Provisioning URI encoded into totp_qr.png")
    print("Scan totp_qr.png with Google Authenticator, Authy, etc.")
    return secret

if __name__ == "__main__":
    account = input("Enter account name (e.g. your email): ")
    secret = create_totp_secret(account)

    totp = pyotp.TOTP(secret)
    print("\nCurrent codes (they change every 30 seconds):")

    try:
        while True:
            code = totp.now()
            remaining = 30 - (int(time.time()) % 30)
            print(f"\rTOTP code: {code}  (valid for {remaining:2d}s)", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")

