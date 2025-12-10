# NSSec Week 3 Lab – Authentication & Password Security

This lab explores basic authentication concepts and common password security mechanisms.  
All scripts are written in Python and were run locally to generate the required screenshots.

## Files in this folder

- `auth_system.py`  
  Simple demo authentication system that asks for a username and password and checks them against stored (hashed) values.

- `brute_force_demo.py`  
  Illustrates how a brute-force attack can try many passwords and why weak passwords are dangerous.

- `hashing_demo.py`  
  Shows how password hashing works using a one-way hash function and why storing plain-text passwords is insecure.

- `password_strength.py`  
  Checks the strength of a user-entered password (length, complexity, etc.) and explains why strong passwords are harder to crack.

- `salt_pepper_demo.py`  
  Demonstrates salting and peppering: adding random per-user salts and a secret pepper value before hashing to protect against rainbow tables and hash reuse.

- `__pycache__/`  
  Auto-generated Python cache files (created when the scripts are run).

- `Screenshot … .png`  
  Screenshots showing each script running successfully in the terminal, as required for the lab submission.

## How to run the scripts

From inside the `NSSec_Week3_Lab` folder:

```bash
python3 auth_system.py
python3 brute_force_demo.py
python3 hashing_demo.py
python3 password_strength.py
python3 salt_pepper_demo.py
