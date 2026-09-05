# EPSS_CVSS_Extract.py
import os
import re
import json
import pickle
import threading
from typing import Dict, Any, List

try:
    with open("cve_dataset.json", "r") as f:
        CVE_DATA = json.load(f)
    CVE_INDEX = {v["cve"]["id"]: v for v in CVE_DATA.get("vulnerabilities", [])}
except FileNotFoundError:
    print("[!] cve_dataset.json not found. Base scores will be N/A.")
    CVE_INDEX = {}

try:
    with open("epss.json", "r") as f:
        EPSS_RAW = json.load(f)
    EPSS_LIST = EPSS_RAW.get("data", []) if isinstance(EPSS_RAW, dict) else EPSS_RAW
    EPSS_INDEX = {item["cve"]: item for item in EPSS_LIST}
except FileNotFoundError:
    print("[!] epss.json not found. EPSS scores will be N/A.")
    EPSS_INDEX = {}


def extract_cvss_from_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    cve = v.get("cve", {})
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss = m.get("cvssData", {})
            return {
                "CVSS_Version": "3.1" if key == "cvssMetricV31" else "3.0" if key == "cvssMetricV30" else "2.0",
                "Base_Score": cvss.get("baseScore"),
                "Severity": m.get("baseSeverity") or m.get("severity"),
                "Vector": cvss.get("vectorString"),
            }
    return {"Base_Score": None}

def get_cvss_v2(cve_id: str) -> Dict[str, Any]:
    v = CVE_INDEX.get(cve_id)
    if not v:
        return {"CVE_ID": cve_id, "Error": "CVE not found in local dataset", "Base_Score": None}
    return {"CVE_ID": cve_id, **extract_cvss_from_vuln(v)}


def get_epss(cve_id: str) -> Dict[str, Any]:
    item = EPSS_INDEX.get(cve_id)
    if not item:
        return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": "CVE not found in local EPSS dataset"}
    try:
        return {
            "EPSS_Score": float(item.get("epss", 0.0)),
            "EPSS_Percentile": float(item.get("percentile", 0.0)),
            "Error": None,
        }
    except Exception as e:
        return {"EPSS_Score": None, "EPSS_Percentile": None, "Error": str(e)}

import re
from typing import List, Dict, Any

def compute_vulnerabilities(filename: str = "output.txt") -> List[Dict[str, Any]]:
    cve_list = []
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                match = re.search(r'(CVE-\d{4}-\d{4,})', line)
                if match:
                    cve_list.append(match.group(1))
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found in the current directory.")
        return []

    cve_list = list(dict.fromkeys(cve_list))

    results = []
    for cve in cve_list:
        print(f"Fetching data for {cve}...")
        cvss_info = get_cvss_v2(cve)  
        epss_info = get_epss(cve)
        
        item = {
            "id": cve,
            "baseScore": cvss_info.get("Base_Score", "N/A"),
            "epssScore": epss_info.get("EPSS_Score"),
            "epssPercentile": epss_info.get("EPSS_Percentile"),
            "epssError": epss_info.get("Error") or cvss_info.get("Error") or None,
        }
        results.append(item)
        
    return results

