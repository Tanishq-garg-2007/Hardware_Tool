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

    # 3. Network Detection & Auto-Sync
    # Offline by default: if no internet, NEVER attempt download; proceed with offline local database.
    # If internet connection is available, automatically update and sync the dataset if needed.
    from cve_updater import auto_sync_if_online
    sync_status = auto_sync_if_online(force=force_db_update)
    print(f"[CVE Scanner] {sync_status['message']}")

    # 4. Load CVE entries (NVD SQLite database or fallback)
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

            parsed_dict = _serialize_dataclass(parsed_info)
            normalized_summary = {
                **parsed_dict,
                "bootloader": parsed_info.bootloader_full_string or (f"U-Boot v{parsed_info.bootloader_version}" if parsed_info.bootloader_version else "") or parsed_dict.get("bootloader") or "N/A",
                "bootloader_version": parsed_info.bootloader_version or parsed_dict.get("bootloader_version") or "N/A",
                "cpu_soc": parsed_info.cpu_raw or parsed_dict.get("cpu_raw") or parsed_dict.get("cpu_soc") or "N/A",
                "architecture": parsed_info.cpu_architecture or parsed_dict.get("cpu_architecture") or parsed_dict.get("architecture") or "N/A",
                "board_model": parsed_info.model_raw or parsed_dict.get("model_raw") or parsed_dict.get("board_model") or "N/A",
                "vendor": ", ".join(sorted(parsed_info.detected_vendors)) if parsed_info.detected_vendors else (parsed_dict.get("vendor") or "N/A"),
                "kernel_version": parsed_info.kernel_version or parsed_dict.get("kernel_version") or "N/A",
                "squashfs_version": parsed_info.squashfs_version or parsed_dict.get("squashfs_version") or "N/A",
                "gcc_version": parsed_info.gcc_version or parsed_dict.get("gcc_version") or "N/A",
                "crypto_algos": sorted(list(parsed_info.crypto_algos)) if parsed_info.crypto_algos else parsed_dict.get("crypto_algos") or [],
                "filesystem_type": ", ".join(sorted(parsed_info.filesystems)) if parsed_info.filesystems else (parsed_dict.get("filesystem_type") or "N/A"),
                "init_drivers": ", ".join(sorted(parsed_info.initialized_drivers)) if parsed_info.initialized_drivers else (parsed_dict.get("init_drivers") or "N/A"),
            }

            results.append({
                "filename": bootlog_file.name,
                "file_path": str(bootlog_file.resolve()),
                "device_summary": normalized_summary,
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
        "scanned_directory": str(path.resolve()),
        "total_files_scanned": len(results),
        "network_mode": "Online" if sync_status.get("online") else "Offline",
        "sync_status": sync_status,
        "results": results
    }


def run_scan_content(
    boot_log_text: str,
    filename: str = "captured_bootlog.txt",
    cve_db_path: str = os.getenv("NVD_DB_DIR", "../data/nvd_db"),
    force_db_update: bool = False,
) -> Dict[str, Any]:
    """
    Saves in-memory boot log string to disk (data/bootlogs/{filename}) and invokes run_scan.
    Guarantees 100% parity with file-based NIST NVD 2.0 scanning.
    """
    backend_dir = Path(__file__).resolve().parent
    bootlogs_dir = backend_dir.parent / "data" / "bootlogs"
    bootlogs_dir.mkdir(parents=True, exist_ok=True)

    target_file = bootlogs_dir / filename
    with open(target_file, "w", encoding="utf-8") as f:
        f.write(boot_log_text or "")

    return run_scan(
        target_path=str(target_file),
        cve_db_path=cve_db_path,
        force_db_update=force_db_update,
    )

