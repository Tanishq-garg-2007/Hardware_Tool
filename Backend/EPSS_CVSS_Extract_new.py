import os
import re
import json
from typing import List, Dict, Any

from EPSS_CVSS_Extract import get_epss, get_cvss_v2


def compute_vulnerabilities1(filename: str = "output.txt") -> List[Dict[str, Any]]:
    """
    Parses scanner output (JSON array or raw text) and enriches all CVE entries
    with CVSS base scores and FIRST EPSS exploitability probabilities from SQLite.
    """
    results_map = {}
    
    if not os.path.exists(filename):
        print(f"Error: The file '{filename}' was not found.")
        return []

    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            cid = item.get("cve_id") or item.get("id") or item.get("cve")
                            if cid:
                                cve_clean = str(cid).strip().upper()
                                bs = item.get("base_score") or item.get("baseScore")
                                results_map[cve_clean] = bs
            except Exception:
                pass

            if not results_map:
                for line in content.splitlines():
                    match_fallback = re.search(r'(CVE-\d{4}-\d{4,})', line, re.IGNORECASE)
                    if match_fallback:
                        cve_id = match_fallback.group(1).upper()
                        if cve_id not in results_map:
                            results_map[cve_id] = None
    except Exception as e:
        print(f"Error: Unable to process '{filename}': {e}")
        return []

    if not results_map:
        return []

    cve_list = list(results_map.keys())

    # High-speed batch lookup
    cvss_batch = {}
    epss_batch = {}
    try:
        from cve_updater import get_cvss_batch, get_epss_batch_from_db
        cvss_batch = get_cvss_batch(cve_list)
        epss_batch = get_epss_batch_from_db(cve_list)
    except Exception:
        pass

    results = []
    for cve, parsed_score in results_map.items():
        cvss_info = cvss_batch.get(cve) or get_cvss_v2(cve)
        epss_info = epss_batch.get(cve) or get_epss(cve)

        score_val = parsed_score
        if score_val is None or score_val in (0.0, "0.0", "", "N/A"):
            score_val = cvss_info.get("Base_Score")
            if score_val is None:
                score_val = "N/A"

        item = {
            "id": cve,
            "baseScore": score_val,
            "severity": cvss_info.get("Severity", "UNRATED"),
            "epssScore": epss_info.get("EPSS_Score"),
            "epssPercentile": epss_info.get("EPSS_Percentile"),
            "epssError": epss_info.get("Error"),
        }
        results.append(item)
        
    return results


if __name__ == "__main__":
    import sys
    
    filename = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    print(f"[*] Processing {filename} for EPSS/CVSS scores...")
    results = compute_vulnerabilities1(filename)
    
    out_file = filename.replace(".json", "").replace(".txt", "") + "_epss.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"[+] Enrichment complete. {len(results)} vulnerabilities enriched.")
    print(f"[+] Saved final results to: {out_file}")
