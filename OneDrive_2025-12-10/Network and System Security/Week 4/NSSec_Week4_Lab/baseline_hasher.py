import hashlib
import csv
import os
from datetime import datetime

FOLDER = "."          # current folder
OUTPUT_CSV = "baseline.csv"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    rows = []
    for name in os.listdir(FOLDER):
        path = os.path.join(FOLDER, name)
        if os.path.isfile(path) and name != OUTPUT_CSV:
            file_hash = sha256_file(path)
            timestamp = datetime.now().isoformat(timespec="seconds")
            rows.append((name, file_hash, timestamp))
            print(f"Hashed {name}: {file_hash[:16]}...")

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["filename", "sha256", "timestamp"])
        writer.writerows(rows)

    print(f"\nBaseline saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
