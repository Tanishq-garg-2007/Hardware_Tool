import os
from dotenv import load_dotenv
load_dotenv()
import dataclasses
from pathlib import Path
from typing import Dict, Any, List

# Import functions & dataclasses from your existing file
from BootLog_Analysis import (
    parse_bootlog,
    scan_bootloader_cves,
    scan_kernel_cves,
    should_update,
    update,
    _load_cve_database,
    BootlogInfo,
    CVEMatch
)


def _serialize_dataclass(obj: Any) -> Any:
    """Recursively converts dataclasses and sets into JSON-serializable dicts/lists."""
    if dataclasses.is_dataclass(obj):
        result = {}
        for field in dataclasses.fields(obj):
            value = getattr(obj, field.name)
            result[field.name] = _serialize_dataclass(value)
        return result
    elif isinstance(obj, set):
        return sorted(list(obj))
    elif isinstance(obj, list):
        return [_serialize_dataclass(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _serialize_dataclass(v) for k, v in obj.items()}
    else:
        return obj


def run_scan(target_path: str, cve_db_path: str = os.getenv("NVD_DB_DIR", "../data/nvd_db"), force_db_update: bool = False) -> Dict[str, Any]:
    """
    Executes CVE scan for a single bootlog file OR all bootlog files in a directory.
    Uses the offline NIST NVD 2.0 database for 100% comprehensive CVSS metrics.
    """
    backend_dir = Path(__file__).resolve().parent
    path = Path(target_path)
    
    # 1. Check if the path exists (with fallbacks for relative offsets & .txt)
    if not path.exists():
        if (backend_dir / target_path).exists():
            path = backend_dir / target_path
        elif (backend_dir.parent / target_path).exists():
            path = backend_dir.parent / target_path
        elif (backend_dir / f"{target_path}.txt").exists():
            path = backend_dir / f"{target_path}.txt"
        elif Path(f"{target_path}.txt").exists():
            path = Path(f"{target_path}.txt")
        else:
            raise FileNotFoundError(f"Target path '{target_path}' does not exist.")

    # Resolve cve_db_path relative paths
    cve_path_obj = Path(cve_db_path)
    if not cve_path_obj.exists():
        if (backend_dir / cve_db_path).exists():
            cve_db_path = str(backend_dir / cve_db_path)
        elif (backend_dir.parent / cve_db_path).exists():
            cve_db_path = str(backend_dir.parent / cve_db_path)

    # 2. Automatically handle single file vs. directory
    if path.is_file():
        bootlog_files = [path]
    elif path.is_dir():
        valid_extensions = {".txt", ".log", ""}
        bootlog_files = [
            f for f in path.iterdir() 
            if f.is_file() and f.suffix.lower() in valid_extensions
        ]
    else:
        raise ValueError(f"Path '{target_path}' is neither a regular file nor a directory.")

    if not bootlog_files:
        raise FileNotFoundError(f"No valid bootlog files found at '{target_path}'.")

    # 3. Load CVE entries (NVD SQLite database or fallback)
    cve_entries = _load_cve_database(cve_db_path)

    # 4. Perform Scan
    results = []
    for bootlog_file in bootlog_files:
        try:
            parsed_info: BootlogInfo = parse_bootlog(str(bootlog_file))

            scan1_matches: List[CVEMatch] = scan_bootloader_cves(
                parsed_info, cve_entries, verbose=False, print_stats=False
            )
            scan2_matches: List[CVEMatch] = scan_kernel_cves(
                parsed_info, cve_entries, verbose=False, print_stats=False
            )

            all_matches = scan1_matches + scan2_matches

            matches_data = []
            for match in all_matches:
                m_dict = _serialize_dataclass(match)

                # Ensure base_score and severity are non-null and accurate
                if not m_dict.get("base_score") or m_dict.get("severity") in (None, "UNKNOWN", ""):
                    try:
                        from cve_updater import get_cvss
                        cvss_meta = get_cvss(match.cve_id)
                        if cvss_meta.get("Base_Score") is not None:
                            m_dict["base_score"] = float(cvss_meta["Base_Score"])
                            m_dict["severity"] = cvss_meta.get("Severity", "UNRATED")
                    except Exception:
                        pass

                try:
                    from EPSS_CVSS_Extract import get_epss
                    epss_res = get_epss(match.cve_id)
                    m_dict["epss_score"] = epss_res.get("EPSS_Score")
                    m_dict["epss_percentile"] = epss_res.get("EPSS_Percentile")
                except Exception:
                    m_dict["epss_score"] = None
                    m_dict["epss_percentile"] = None
                matches_data.append(m_dict)

            results.append({
                "filename": bootlog_file.name,
                "file_path": str(bootlog_file.resolve()),
                "device_summary": _serialize_dataclass(parsed_info),
                "summary_text": parsed_info.summary(),
                "cve_count": len(all_matches),
                "matches": matches_data
            })
        except Exception as e:
            results.append({
                "filename": bootlog_file.name,
                "file_path": str(bootlog_file.resolve()),
                "error": str(e)
            })

    return {
        "scanned_path": str(path.resolve()),
        "total_files_scanned": len(results),
        "results": results
    }
