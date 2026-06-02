def explain(cve: dict) -> str:
    cve_id = cve.get("cve_id", "Unknown CVE")
    risk_score = cve.get("risk_score", 0)
    risk_label = cve.get("risk_label", "Unknown")
    severity_score = cve.get("severity_score", 0)
    cwe = cve.get("cwe", "Unknown")
    is_kev = cve.get("is_kev", False)
    has_exploit = cve.get("has_exploit", False)
    cluster_label = cve.get("cluster_label", "")
    is_anomaly = cve.get("is_anomaly", False)
    required_action = cve.get("requiredAction") or ""
    description = (cve.get("description") or "")[:200]

    parts = [f"{cve_id} carries a {risk_label} risk score of {risk_score:.1f}/10 (CVSS base: {severity_score:.1f})."]

    if is_kev and has_exploit:
        parts.append("It is actively exploited in the wild (CISA KEV) and has a public exploit available — treat as top priority.")
    elif is_kev:
        parts.append("It is listed in the CISA Known Exploited Vulnerabilities catalog, meaning it is actively exploited in the wild.")
    elif has_exploit:
        exploit_type = (cve.get("exploit_type") or "").strip()
        exploit_verified = cve.get("exploit_verified", False)
        exploit_desc = "A verified" if exploit_verified else "A public"
        exploit_kind = f" {exploit_type}" if exploit_type else ""
        parts.append(f"{exploit_desc}{exploit_kind} exploit exists for this vulnerability, raising its real-world danger significantly.")
    else:
        parts.append("No public exploit or KEV listing found at this time.")

    epss = cve.get("epss_score", 0) or 0
    epss_pct = cve.get("epss_percentile", 0) or 0
    if epss > 0.1:
        parts.append(f"EPSS score: {epss:.4f} ({epss_pct*100:.1f}th percentile) — this CVE has an above-average probability of being exploited in the next 30 days.")
    elif epss > 0:
        parts.append(f"EPSS score: {epss:.4f} ({epss_pct*100:.1f}th percentile).")

    av = (cve.get("attack_vector") or "").strip()
    pr = (cve.get("privileges_required") or "").strip()
    ui = (cve.get("user_interaction") or "").strip()
    if av == "Network" and pr == "None" and ui == "None":
        parts.append("Attack profile: remotely exploitable over the network, requires no authentication and no user interaction — highest exploitability class.")

    if cwe and cwe != "UNKNOWN":
        parts.append(f"Weakness type: {cwe}.")

    if cluster_label:
        parts.append(f"This CVE belongs to the '{cluster_label}' vulnerability family.")

    if is_anomaly:
        parts.append("Anomaly detected: this CVE has an unusual risk profile compared to others with a similar CVSS score — investigate further.")

    action = required_action.strip() if required_action else ""
    if action:
        parts.append(f"CISA recommended action: {action}")
    elif risk_label == "Critical":
        parts.append("Recommended action: Apply vendor patch immediately. Escalate to security team.")
    elif risk_label == "High":
        parts.append("Recommended action: Patch within 7 days. Monitor for active exploitation.")
    elif risk_label == "Medium":
        parts.append("Recommended action: Schedule patching within 30 days. Review exposure.")
    else:
        parts.append("Recommended action: Apply patch in the next maintenance window.")

    vendor = (cve.get("vendorProject") or "").strip()
    product = (cve.get("product") or "").strip()
    if vendor and risk_label in ("Critical", "High"):
        target_str = f"{vendor} / {product}" if product else vendor
        parts.append(f"Affected vendor/product: {target_str}.")

    due = (cve.get("dueDate") or "").strip()
    if due and is_kev:
        parts.append(f"CISA mandatory patch deadline: {due[:10]}.")

    if (cve.get("ransomware_campaign") or "").strip() == "Known":
        parts.append("WARNING: This CVE has been associated with known ransomware campaigns — treat as highest priority regardless of CVSS score.")

    return " ".join(parts)
