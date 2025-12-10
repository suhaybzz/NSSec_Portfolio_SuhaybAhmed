import hashlib
import csv
import os

BASELINE_CSV = "baseline.csv"
FOLDER = "."

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def load_baseline():
    baseline = {}
    with open(BASELINE_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            baseline[row["filename"]] = row["sha256"]
    return baseline

def main():
    baseline = load_baseline()

    current_hashes = {}
    for name in os.listdir(FOLDER):
        path = os.path.join(FOLDER, name)
        if os.path.isfile(path) and name != BASELINE_CSV:
            current_hashes[name] = sha256_file(path)

    modified = []
    deleted = []
    new_files = []

    for name, old_hash in baseline.items():
        if name not in current_hashes:
            deleted.append(name)
        elif current_hashes[name] != old_hash:
            modified.append(name)

    for name in current_hashes:
        if name not in baseline:
            new_files.append(name)

    print("=== File change report ===")
    print("Modified:", modified or "None")
    print("Deleted:", deleted or "None")
    print("New files:", new_files or "None")

if __name__ == "__main__":
    main()
