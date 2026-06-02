"""
Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

EPSS gives every CVE a daily probability (0-1) of being exploited within
the next 30 days, plus a percentile rank vs all other CVEs.

Output: backend/Data/epss_scores.csv
Columns: cve, epss, percentile
"""
import gzip
import io
import os
import requests

URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "backend", "Data", "epss_scores.csv")


def fetch_epss():
    print("[EPSS] Downloading scores from epss.cyentia.com ...")
    resp = requests.get(URL, timeout=60)
    resp.raise_for_status()

    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as f:
        content = f.read()

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write(content)

    lines = [l for l in content.splitlines() if not l.startswith("#")]
    print(f"[EPSS] Saved {len(lines) - 1:,} CVE scores to {OUTPUT}")


if __name__ == "__main__":
    fetch_epss()
