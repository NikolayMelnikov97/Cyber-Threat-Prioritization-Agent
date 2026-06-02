"""
Parse the MITRE ATT&CK Enterprise STIX JSON and extract CVE references.

Run fetch_mitre_attack.py first to download enterprise-attack.json.

Output: backend/Data/mitre_cve_links.csv
Columns: cve_id, technique_id, technique_name, tactic
"""
import csv
import json
import os
import re

INPUT = os.path.join(os.path.dirname(__file__), "..", "enterprise-attack.json")
OUTPUT = os.path.join(os.path.dirname(__file__), "..", "backend", "Data", "mitre_cve_links.csv")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_mitre():
    if not os.path.exists(INPUT):
        print(f"[MITRE] {INPUT} not found. Run fetch_mitre_attack.py first.")
        return

    print(f"[MITRE] Loading {INPUT} ...")
    with open(INPUT, encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])

    # Build technique id → {name, tactics} map
    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not tech_id:
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        techniques[obj["id"]] = {
            "technique_id": tech_id,
            "technique_name": obj.get("name", ""),
            "tactic": ",".join(tactics),
            "description": obj.get("description", ""),
        }

    # Extract CVE references from technique descriptions and external refs
    rows: list[dict] = []
    seen: set[tuple] = set()
    for stix_id, tech in techniques.items():
        cve_ids = set(CVE_RE.findall(tech["description"]))
        # Also check external references for CVE source entries
        for obj in objects:
            if obj.get("id") != stix_id:
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name", "").upper() == "CVE" or CVE_RE.match(ref.get("external_id", "")):
                    cve_ids.add(ref["external_id"].upper())
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            key = (cve_id, tech["technique_id"])
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "cve_id": cve_id,
                "technique_id": tech["technique_id"],
                "technique_name": tech["technique_name"],
                "tactic": tech["tactic"],
            })

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "technique_id", "technique_name", "tactic"])
        writer.writeheader()
        writer.writerows(rows)

    unique_cves = len({r["cve_id"] for r in rows})
    print(f"[MITRE] Saved {len(rows)} technique-CVE links ({unique_cves} unique CVEs) to {OUTPUT}")


if __name__ == "__main__":
    parse_mitre()
