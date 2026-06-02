"""
Fetch Open Source Vulnerability (OSV) data from Google's osv.dev.

Covers vulnerabilities in: PyPI, npm, Maven, Go, Rust, RubyGems, and more.
Each entry maps to a CVE ID and includes exact package names + affected versions.

Output: backend/Data/osv_packages.csv
Columns: osv_id, cve_id, ecosystem, package_name, affected_versions, fixed_version, severity
"""
import csv
import io
import json
import os
import zipfile
import requests

ECOSYSTEMS = ["PyPI", "npm", "Maven", "Go", "RubyGems", "crates.io"]
BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "backend", "Data", "osv_packages.csv")


def _extract_cve_ids(osv_entry: dict) -> list[str]:
    aliases = osv_entry.get("aliases", [])
    ids = [osv_entry.get("id", "")] + aliases
    return [i for i in ids if i.upper().startswith("CVE-")]


def _extract_packages(osv_entry: dict) -> list[dict]:
    rows = []
    for affected in osv_entry.get("affected", []):
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        package_name = pkg.get("name", "")
        if not package_name:
            continue
        # Collect affected version ranges
        ranges_str_parts = []
        fixed_version = ""
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "introduced" in event:
                    ranges_str_parts.append(f">={event['introduced']}")
                if "fixed" in event:
                    fixed_version = event["fixed"]
                    ranges_str_parts.append(f"<{event['fixed']}")
        affected_versions = ",".join(ranges_str_parts) or ",".join(affected.get("versions", [])[:10])
        severity = ""
        for s in osv_entry.get("severity", []):
            if s.get("type") in ("CVSS_V3", "CVSS_V4"):
                severity = s.get("score", "")
                break
        rows.append({
            "ecosystem": ecosystem,
            "package_name": package_name,
            "affected_versions": affected_versions[:500],
            "fixed_version": fixed_version,
            "severity": severity,
        })
    return rows


def fetch_osv():
    all_rows: list[dict] = []

    for ecosystem in ECOSYSTEMS:
        url = BASE_URL.format(ecosystem=ecosystem)
        print(f"[OSV] Downloading {ecosystem} from {url} ...")
        try:
            resp = requests.get(url, timeout=120)
            resp.raise_for_status()
        except Exception as e:
            print(f"[OSV] Failed to download {ecosystem}: {e}")
            continue

        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            names = z.namelist()
            for name in names:
                if not name.endswith(".json"):
                    continue
                try:
                    entry = json.loads(z.read(name))
                except Exception:
                    continue
                osv_id = entry.get("id", "")
                cve_ids = _extract_cve_ids(entry)
                packages = _extract_packages(entry)
                if not packages:
                    continue
                for cve_id in (cve_ids or [""]):
                    for pkg in packages:
                        all_rows.append({
                            "osv_id": osv_id,
                            "cve_id": cve_id.upper(),
                            **pkg,
                        })

        print(f"[OSV] {ecosystem}: processed {len(names)} entries")

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["osv_id", "cve_id", "ecosystem", "package_name",
                        "affected_versions", "fixed_version", "severity"],
        )
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"[OSV] Saved {len(all_rows):,} package entries to {OUTPUT}")


if __name__ == "__main__":
    fetch_osv()
