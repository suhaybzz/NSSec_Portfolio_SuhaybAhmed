import re

sample = "Procmon.exe"

data = open(sample, "rb").read().decode(errors="ignore")

urls = re.findall(r"https?://[^\s\"']+", data)
ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", data)

print("URLs found:", urls)
print("IPs found:", ips)
