import pandas as pd

# =========================================================
# CISA KEV Downloader
# ---------------------------------------------------------
# Purpose:
# Download the CISA Known Exploited Vulnerabilities catalog
# and save it locally as a CSV file.
# =========================================================

KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


def fetch_kev() -> pd.DataFrame:
    """
    Download the KEV catalog directly from CISA.
    """
    df = pd.read_csv(KEV_URL)
    return df


def save_dataset(df: pd.DataFrame, filename: str):
    """
    Save the KEV dataset to a local CSV file.
    """
    df.to_csv(filename, index=False, encoding="utf-8-sig")
    print(f"[INFO] Dataset saved to {filename}")


def main():
    """
    Main execution flow.
    """
    print("[START] Downloading KEV dataset...")

    df = fetch_kev()
    save_dataset(df, "cisa_kev.csv")

    print("[DONE]")
    print(f"[INFO] Final dataset shape: {df.shape}")
    print(df.head())


if __name__ == "__main__":
    main()