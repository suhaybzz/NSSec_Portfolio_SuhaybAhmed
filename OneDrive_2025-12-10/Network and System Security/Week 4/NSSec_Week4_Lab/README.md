# NSSec_Week4_Lab – Malware & Integrity Monitoring

This folder contains my solutions for the **Week 4 Networks & Systems Security lab**, focused on basic malware detection and file-integrity monitoring using Python.

## Files

- `baseline_hasher.py`  
  Calculates and saves baseline cryptographic hashes for a set of files so later changes can be detected.

- `change_detector.py`  
  Recomputes hashes and compares them with the saved baseline to flag files that have been modified, added, or deleted.

- `monitor_prototype.py`  
  Simple prototype that ties the hashing and change-detection together to act like a basic integrity-monitoring tool.

- `worm_sim.py`  
  Simulates a very simple “worm-like” behaviour by copying itself to other files/locations (purely for teaching purposes).

- `signature_scanner.py`  
  Scans files in a chosen folder for suspicious patterns / “signatures” that could indicate malware.

## How to Run

From inside this folder:

```bash
python3 baseline_hasher.py
python3 change_detector.py
python3 monitor_prototype.py
python3 worm_sim.py
python3 signature_scanner.py
