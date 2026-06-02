import requests

# =========================================================
# MITRE ATT&CK Downloader
# ---------------------------------------------------------
# Purpose:
# Download the official MITRE ATT&CK Enterprise dataset
# from the official MITRE ATT&CK STIX repository and save
# it locally as a JSON file.
#
# Source:
# https://github.com/mitre-attack/attack-stix-data
# =========================================================

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

OUTPUT_FILE = "enterprise-attack.json"


def download_mitre_attack():
    """
    Download the official MITRE ATT&CK Enterprise dataset
    and save it as a local JSON file.
    """
    print("[START] Downloading official MITRE ATT&CK Enterprise dataset...")

    response = requests.get(MITRE_ATTACK_URL, timeout=120)
    response.raise_for_status()

    with open(OUTPUT_FILE, "wb") as f:
        f.write(response.content)

    print(f"[DONE] File saved as: {OUTPUT_FILE}")


if __name__ == "__main__":
    download_mitre_attack()