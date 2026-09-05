import json
import re
from typing import List, Dict, Any

# 1. Lazy load the 21.5 MB local EPSS dataset into memory
EPSS_INDEX = None

def _load_epss_lazy():
    global EPSS_INDEX
    if EPSS_INDEX is not None:
        return
        
    EPSS_INDEX = {}
    try:
        with open("epss.json", "r", encoding="utf-8") as f:
            EPSS_RAW = json.load(f)
        # The file contains a JSON array directly: [{"cve": "...", "epss": ...}]
        EPSS_LIST = EPSS_RAW.get("data", []) if isinstance(EPSS_RAW, dict) else EPSS_RAW
        for item in EPSS_LIST:
            EPSS_INDEX[item["cve"]] = item
    except FileNotFoundError:
        print("[!] epss.json not found. EPSS scores will be N/A.")
    except json.JSONDecodeError as e:
        print(f"[!] epss.json is not a valid JSON file. Error: {e}")

def get_epss(cve_id: str) -> Dict[str, Any]:
    _load_epss_lazy()
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

def compute_vulnerabilities1(filename: str = "output.txt") -> List[Dict[str, Any]]:
    results_map = {}
    
    # 2. Extract CVSS directly from the scanner's JSON output (100% offline from MITRE db_temp)
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            try:
                data = json.load(file)
                for item in data:
                    cve_id = item.get("cve_id")
                    if cve_id:
                        bs = item.get("base_score")
                        results_map[cve_id] = bs
            except json.JSONDecodeError:
                # Fallback if it's not JSON
                file.seek(0)
                for line in file:
                    match_fallback = re.search(r'(CVE-\d{4}-\d{4,})', line)
                    if match_fallback:
                        cve_id = match_fallback.group(1)
                        if cve_id not in results_map:
                            results_map[cve_id] = "N/A"
                        
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return []

    # 3. Combine them
    results = []
    for cve, base_score in results_map.items():
        epss_info = get_epss(cve)
        
        item = {
            "id": cve,
            "baseScore": base_score if (base_score != 0.0 and base_score != "0.0") else "N/A",
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
