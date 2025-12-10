import os
import re

FOLDER = "."

SIGNATURES = [
    r"eval\(",
    r"base64\.b64decode",
    r"socket\.connect",
    r"exec\(",
    r"import os"
]

def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        print(f"Could not read {path}: {e}")
        return []

    hits = []
    for sig in SIGNATURES:
        if re.search(sig, content):
            hits.append(sig)
    return hits

def main():
    print("=== Signature scan ===")
    for name in os.listdir(FOLDER):
        path = os.path.join(FOLDER, name)
        if os.path.isfile(path) and name.endswith(".py"):
            hits = scan_file(path)
            if hits:
                print(f"{name}: suspicious patterns -> {hits}")

if __name__ == "__main__":
    main()
