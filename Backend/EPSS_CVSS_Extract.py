# EPSS_CVSS_Extract.py
import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List

# Optional fallback indices if user places local json files
CVE_INDEX = {}
if os.path.exists("cve_dataset.json"):
    try:
        with open("cve_dataset.json", "r", encoding="utf-8") as f:
            CVE_DATA = json.load(f)
        CVE_INDEX = {v["cve"]["id"]: v for v in CVE_DATA.get("vulnerabilities", []) if "cve" in v and "id" in v["cve"]}
    except Exception:
        CVE_INDEX = {}

EPSS_INDEX = {}
if os.path.exists("epss.json"):
    try:
        with open("epss.json", "r", encoding="utf-8") as f:
            EPSS_RAW = json.load(f)
        EPSS_LIST = EPSS_RAW.get("data", []) if isinstance(EPSS_RAW, dict) else EPSS_RAW
        EPSS_INDEX = {item["cve"]: item for item in EPSS_LIST if isinstance(item, dict) and "cve" in item}
    except Exception:
        EPSS_INDEX = {}


def extract_cvss_from_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    cve = v.get("cve", {})
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss = m.get("cvssData", {})
            return {
                "CVSS_Version": "3.1" if key == "cvssMetricV31" else "3.0" if key == "cvssMetricV30" else "4.0" if key == "cvssMetricV40" else "2.0",
                "Base_Score": cvss.get("baseScore", "N/A"),
                "Severity": m.get("baseSeverity") or m.get("severity") or "UNRATED",
                "Vector": cvss.get("vectorString", ""),
            }
    return {"Base_Score": "N/A", "Severity": "UNRATED"}


def get_cvss_v2(cve_id: str) -> Dict[str, Any]:
    """
    Retrieves CVSS metrics for a CVE ID.
    Primary: Local offline NIST NVD SQLite database (391k+ records).
    Fallback: In-memory CVE_INDEX if cve_dataset.json is present.
    """
    clean_id = (cve_id or "").strip().upper()
    try:
        from cve_updater import get_cvss
        res = get_cvss(clean_id)
        if res and res.get("Base_Score") is not None:
            return res
    except Exception:
        pass

    v = CVE_INDEX.get(clean_id)
    if not v:
        return {"CVE_ID": clean_id, "Error": None, "Base_Score": "N/A", "Severity": "UNRATED"}
    return {"CVE_ID": clean_id, **extract_cvss_from_vuln(v)}


def get_epss(cve_id: str) -> Dict[str, Any]:
    """
    Retrieves EPSS exploitability score and percentile for a given CVE ID.
    Primary: Local offline SQLite database (372k+ records in nvd_cves.db).
    Fallback 1: Local epss.json file if provided.
    Fallback 2: Real-time FIRST REST API if online.
    """
    clean_id = (cve_id or "").strip().upper()
    if not clean_id:
        return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": "Empty CVE ID"}

    # 1. Primary: query complete SQLite database
    try:
        from cve_updater import get_epss_from_db
        db_res = get_epss_from_db(clean_id)
        if db_res and db_res.get("EPSS_Score") is not None:
            return db_res
    except Exception:
        pass

    # 2. Secondary fallback: check local EPSS_INDEX
    item = EPSS_INDEX.get(clean_id)
    if item:
        try:
            return {
                "EPSS_Score": float(item.get("epss", 0.0)),
                "EPSS_Percentile": float(item.get("percentile", 0.0)),
                "Error": None,
            }
        except Exception as e:
            return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": str(e)}

    return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": "CVE not found in local EPSS dataset"}


def compute_vulnerabilities(filename: str = "output.txt") -> List[Dict[str, Any]]:
    """
    Extracts CVE IDs from a text or JSON report file and enriches each CVE
    with CVSS base score, severity, EPSS probability, and EPSS percentile.
    """
    cve_list = []
    
    if not os.path.exists(filename):
        print(f"Error: The file '{filename}' was not found.")
        return []

    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            # Try parsing as JSON first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            cid = item.get("cve_id") or item.get("id") or item.get("cve")
                            if cid:
                                cve_list.append(str(cid).strip().upper())
            except Exception:
                pass

            # Regex search across entire content
            matches = re.findall(r'(CVE-\d{4}-\d{4,})', content, re.IGNORECASE)
            cve_list.extend([m.upper() for m in matches])
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        return []

    cve_list = list(dict.fromkeys(cve_list))
    if not cve_list:
        return []

    # Batch retrieve for high speed
    cvss_batch = {}
    epss_batch = {}
    try:
        from cve_updater import get_cvss_batch, get_epss_batch_from_db
        cvss_batch = get_cvss_batch(cve_list)
        epss_batch = get_epss_batch_from_db(cve_list)
    except Exception:
        pass

    results = []
    for cve in cve_list:
        cvss_info = cvss_batch.get(cve) or get_cvss_v2(cve)
        epss_info = epss_batch.get(cve) or get_epss(cve)
        
        score_val = cvss_info.get("Base_Score")
        if score_val is None or score_val == "None":
            score_val = "N/A"

        item = {
            "id": cve,
            "baseScore": score_val,
            "severity": cvss_info.get("Severity", "UNRATED"),
            "epssScore": epss_info.get("EPSS_Score"),
            "epssPercentile": epss_info.get("EPSS_Percentile"),
            "epssError": epss_info.get("Error") or cvss_info.get("Error") or None,
        }
        results.append(item)
        
    return results


if __name__ == "__main__":
    import sys
    test_cves = ["CVE-2019-14193", "CVE-2019-14194", "CVE-2019-14195"]
    print("Testing EPSS_CVSS_Extract.py with sample CVEs:")
    for c in test_cves:
        cvss = get_cvss_v2(c)
        epss = get_epss(c)
        print(f"  {c} -> CVSS: {cvss.get('Base_Score')} ({cvss.get('Severity')}), EPSS: {epss.get('EPSS_Score')} ({epss.get('EPSS_Percentile')})")
