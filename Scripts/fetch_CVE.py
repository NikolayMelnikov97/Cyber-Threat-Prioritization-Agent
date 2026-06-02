import os
import time
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

# =========================================================
# NVD CVE Downloader - Latest 20,000 CVEs starting from 2026
# ---------------------------------------------------------
# Purpose:
# Download up to 20,000 CVE records starting from year 2026
# and moving backward in time in 120-day windows.
#
# Final output:
# A CSV file sorted from newest to oldest by published date.
# =========================================================

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
TARGET_RECORDS = 20000
WINDOW_DAYS = 120
SLEEP_SECONDS = 1.2
REQUEST_TIMEOUT = 60
MAX_RETRIES = 3


def get_headers() -> Dict[str, str]:
    """
    Build request headers.
    If an API key exists in environment variables, include it.
    """
    api_key = os.getenv("NVD_API_KEY")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def format_nvd_datetime(dt: datetime) -> str:
    """
    Convert datetime to the NVD API expected format.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def extract_english_description(descriptions: List[Dict[str, Any]]) -> str:
    """
    Extract the English description from the descriptions list.
    """
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def extract_cvss_metrics(metrics: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    """
    Extract CVSS data using the following priority:
    CVSS v3.1 -> CVSS v3.0 -> CVSS v2
    """
    result = {
        "severity_score": None,
        "severity_label": None,
        "cvss_vector": None,
        "cvss_version": None,
    }

    try:
        if metrics.get("cvssMetricV31"):
            cvss = metrics["cvssMetricV31"][0]
            result["severity_score"] = cvss["cvssData"].get("baseScore")
            result["severity_label"] = cvss.get("baseSeverity")
            result["cvss_vector"] = cvss["cvssData"].get("vectorString")
            result["cvss_version"] = "3.1"
            return result

        if metrics.get("cvssMetricV30"):
            cvss = metrics["cvssMetricV30"][0]
            result["severity_score"] = cvss["cvssData"].get("baseScore")
            result["severity_label"] = cvss.get("baseSeverity")
            result["cvss_vector"] = cvss["cvssData"].get("vectorString")
            result["cvss_version"] = "3.0"
            return result

        if metrics.get("cvssMetricV2"):
            cvss = metrics["cvssMetricV2"][0]
            result["severity_score"] = cvss["cvssData"].get("baseScore")
            result["severity_label"] = cvss.get("baseSeverity")
            result["cvss_vector"] = cvss["cvssData"].get("vectorString")
            result["cvss_version"] = "2.0"
            return result

    except (KeyError, IndexError, TypeError):
        pass

    return result


def extract_cwes(weaknesses: List[Dict[str, Any]]) -> Optional[str]:
    """
    Extract CWE values and return them as a comma-separated string.
    """
    cwe_list = []

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                cwe_list.append(value)

    unique_cwes = sorted(set(cwe_list))
    return ", ".join(unique_cwes) if unique_cwes else None


def parse_cve_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw CVE object into a flat structured record.
    """
    cve = item.get("cve", {})
    description = extract_english_description(cve.get("descriptions", []))
    metrics_data = extract_cvss_metrics(cve.get("metrics", {}))

    return {
        "cve_id": cve.get("id", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "description": description,
        "description_length": len(description),
        "severity_score": metrics_data["severity_score"],
        "severity_label": metrics_data["severity_label"],
        "cvss_vector": metrics_data["cvss_vector"],
        "cvss_version": metrics_data["cvss_version"],
        "cwe": extract_cwes(cve.get("weaknesses", [])),
        "references_count": len(cve.get("references", [])),
    }


def fetch_page(pub_start: str, pub_end: str, start_index: int) -> Dict[str, Any]:
    """
    Fetch one page from the NVD API for a given published date range.
    """
    headers = get_headers()
    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                BASE_URL,
                headers=headers,
                params=params,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            print(f"[WARNING] Attempt {attempt}/{MAX_RETRIES} failed: {e}")
            time.sleep(2)

    raise RuntimeError(
        f"Failed to fetch page for range {pub_start} -> {pub_end}, startIndex={start_index}"
    )


def fetch_latest_cves_from_2026(target_records: int = TARGET_RECORDS) -> pd.DataFrame:
    """
    Fetch CVEs starting from 2026 and moving backward in time
    until the target number of records is reached.
    """
    all_records = []
    seen_ids = set()

    # Start from the end of 2026
    window_end = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    oldest_allowed = datetime(1999, 1, 1, tzinfo=timezone.utc)

    while len(all_records) < target_records and window_end > oldest_allowed:
        window_start = window_end - timedelta(days=WINDOW_DAYS)

        pub_start = format_nvd_datetime(window_start)
        pub_end = format_nvd_datetime(window_end)

        print(f"[INFO] Fetching range: {pub_start} -> {pub_end}")

        start_index = 0

        while True:
            data = fetch_page(pub_start, pub_end, start_index)
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not vulnerabilities:
                break

            for item in vulnerabilities:
                parsed = parse_cve_item(item)

                if parsed["cve_id"] not in seen_ids:
                    all_records.append(parsed)
                    seen_ids.add(parsed["cve_id"])

                    if len(all_records) >= target_records:
                        break

            print(
                f"[INFO] Window progress: {min(start_index + RESULTS_PER_PAGE, total_results)} / {total_results} | "
                f"Total collected: {len(all_records)} / {target_records}"
            )

            if len(all_records) >= target_records:
                break

            start_index += RESULTS_PER_PAGE
            if start_index >= total_results:
                break

            time.sleep(SLEEP_SECONDS)

        # Move one window backward
        window_end = window_start - timedelta(milliseconds=1)
        time.sleep(SLEEP_SECONDS)

    df = pd.DataFrame(all_records)

    # Sort final dataset from newest to oldest
    df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    df = df.sort_values(by="published", ascending=False).head(target_records)

    return df


def save_dataset(df: pd.DataFrame, filename: str):
    """
    Save the final dataset to CSV.
    """
    df.to_csv(filename, index=False, encoding="utf-8-sig")
    print(f"[INFO] Dataset saved to {filename}")


def main():
    """
    Main execution flow.
    """
    print("[START] Downloading the latest 20,000 CVEs starting from 2026...")

    df = fetch_latest_cves_from_2026(target_records=20000)
    save_dataset(df, "latest_20k_cves_from_2026.csv")

    print("[DONE]")
    print(f"[INFO] Final dataset shape: {df.shape}")
    print(df.head())


if __name__ == "__main__":
    main()