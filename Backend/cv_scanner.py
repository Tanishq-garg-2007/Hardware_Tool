"""
NIST NVD 2.0 Bootlog Vulnerability Scanner
Replaces legacy MITRE dataset crawler with high-speed, 100% offline-capable NIST NVD 2.0 SQLite engine.
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List

def should_update() -> bool:
    try:
        from cve_updater import check_should_update, is_internet_available
        if not is_internet_available():
            return False
        return check_should_update().get("needs_update", False)
    except Exception:
        return False

def update() -> bool:
    try:
        from cve_updater import trigger_database_update, is_internet_available
        if not is_internet_available():
            print("[CVE Scanner] Offline mode active: Skipping remote database update.")
            return False
        print("[CVE Scanner] Triggering NIST NVD database sync...")
        trigger_database_update(force=False)
        return True
    except Exception as e:
        print(f"[CVE Scanner] Error checking database updates: {e}")
        return False

def scan_bootlog_nvd(text: str) -> Dict[str, Any]:
    """
    Scans raw bootlog text against the local NIST NVD 2.0 SQLite database
    (390,572 CVE records) using deep structural analysis, architecture/firmware
    signature extraction, and semver range evaluation.
    """
    if not text or not text.strip():
        return {
            "report_text": "No boot log data provided. Please capture a boot log or provide boot log text to analyze.",
            "matches": [],
            "summary": {},
            "cve_count": 0,
            "severity_breakdown": {},
            "database": "NIST National Vulnerability Database (NVD 2.0)"
        }

    # Write text to temporary file for BootLog_Analysis.parse_bootlog
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
        tmp_path = tmp.name

    try:
        from BootLog_Analysis import parse_bootlog, scan_bootloader_cves, scan_kernel_cves, _load_cve_database
        from cve_updater import get_cvss, count_cves

        parsed_info = parse_bootlog(tmp_path)
        cve_entries = _load_cve_database()

        scan1_matches = scan_bootloader_cves(parsed_info, cve_entries, verbose=False, print_stats=False)
        scan2_matches = scan_kernel_cves(parsed_info, cve_entries, verbose=False, print_stats=False)

        all_matches = scan1_matches + scan2_matches

        # Deduplicate matches by cve_id
        seen = set()
        deduped = []
        for m in all_matches:
            if m.cve_id not in seen:
                seen.add(m.cve_id)
                deduped.append(m)

        # Enrich with CVSS & EPSS
        matches_data = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNRATED": 0}

        for match in deduped:
            m_dict = {
                "cve_id": match.cve_id,
                "severity": match.severity or "UNRATED",
                "base_score": match.base_score,
                "published": match.published,
                "description": match.description,
                "matched_product": match.matched_product,
                "matched_vendor": match.matched_vendor,
                "matched_version_range": match.matched_version_range,
                "scan": match.scan,
                "subsystem": match.subsystem,
                "feature_proof": match.feature_proof,
                "references": match.references or [],
            }

            if not m_dict.get("base_score") or m_dict.get("severity") in (None, "UNKNOWN", "", "UNRATED"):
                try:
                    meta = get_cvss(match.cve_id)
                    if meta.get("Base_Score") is not None:
                        m_dict["base_score"] = float(meta["Base_Score"])
                        m_dict["severity"] = meta.get("Severity", "UNRATED")
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

            sev_key = (m_dict.get("severity") or "UNRATED").upper()
            if sev_key.startswith("CRIT"):
                severity_counts["CRITICAL"] += 1
            elif sev_key.startswith("HIGH"):
                severity_counts["HIGH"] += 1
            elif sev_key.startswith("MED"):
                severity_counts["MEDIUM"] += 1
            elif sev_key.startswith("LOW"):
                severity_counts["LOW"] += 1
            else:
                severity_counts["UNRATED"] += 1

            matches_data.append(m_dict)

        # Sort by CVSS base score descending
        matches_data.sort(key=lambda x: float(x.get("base_score") or 0.0), reverse=True)

        total_loaded = count_cves()

        # Build clean monospace report text
        lines = []
        lines.append("=" * 80)
        lines.append("           NIST NVD 2.0 VULNERABILITY AUDIT REPORT")
        lines.append(f"  Database: NIST National Vulnerability Database (NVD 2.0)")
        lines.append(f"  Catalog Size: {total_loaded:,} CVE records loaded (Offline Local Database)")
        lines.append("=" * 80)
        lines.append("")
        lines.append("[+] EXTRACTED HARDWARE & SYSTEM SIGNATURES:")
        if parsed_info.bootloader_full_string or parsed_info.bootloader_version:
            bl_str = parsed_info.bootloader_full_string or f"U-Boot v{parsed_info.bootloader_version}"
            lines.append(f"  • Bootloader:    {bl_str}")
        if parsed_info.cpu_raw or parsed_info.cpu_architecture:
            lines.append(f"  • SoC / CPU:     {parsed_info.cpu_raw or 'Embedded SoC'} ({parsed_info.cpu_architecture or 'unknown arch'})")
        if parsed_info.model_raw:
            lines.append(f"  • Board Model:   {parsed_info.model_raw}")
        if parsed_info.kernel_version:
            lines.append(f"  • Linux Kernel:  v{parsed_info.kernel_version}")
        if parsed_info.busybox_version:
            lines.append(f"  • BusyBox:       v{parsed_info.busybox_version}")
        if parsed_info.filesystems:
            lines.append(f"  • Filesystems:   {', '.join(sorted(parsed_info.filesystems))}")
        if parsed_info.crypto_algos:
            lines.append(f"  • Crypto Algos:  {', '.join(sorted(parsed_info.crypto_algos))}")
        if parsed_info.leaked_secrets:
            lines.append(f"  • Leaked Keys:   {', '.join(parsed_info.leaked_secrets)}")
        lines.append("")
        lines.append(f"[!] VULNERABILITY FINDINGS ({len(matches_data)} CVEs matched):")
        lines.append("-" * 80)

        if not matches_data:
            lines.append("  No known CVE vulnerabilities matched the detected component versions.")
        else:
            for idx, m in enumerate(matches_data, 1):
                sev = (m.get("severity") or "UNRATED").upper()
                score = m.get("base_score")
                score_str = f"CVSS: {score}" if score is not None else "CVSS: N/A"
                epss = m.get("epss_score")
                epss_pct = m.get("epss_percentile")
                epss_str = f" | EPSS: {epss:.3f} ({int(epss_pct*100)}th pct)" if epss is not None and epss_pct is not None else ""

                lines.append(f"{idx:02d}. [{sev}] {m['cve_id']}  ({score_str}{epss_str})")
                lines.append(f"    Product:    {m.get('matched_product') or 'Firmware'} ({m.get('matched_version_range') or 'All Versions'})")
                if m.get("subsystem"):
                    lines.append(f"    Subsystem:  {m.get('subsystem')}")
                desc = m.get("description") or ""
                if desc:
                    clean_desc = desc.replace("\n", " ").strip()
                    if len(clean_desc) > 160:
                        clean_desc = clean_desc[:157] + "..."
                    lines.append(f"    Summary:    {clean_desc}")
                lines.append(f"    Advisory:   https://nvd.nist.gov/vuln/detail/{m['cve_id']}")
                lines.append("")

        lines.append("=" * 80)
        lines.append(f"SUMMARY: {len(matches_data)} CVEs | {severity_counts['CRITICAL']} Critical | {severity_counts['HIGH']} High | {severity_counts['MEDIUM']} Medium | {severity_counts['LOW']} Low")
        lines.append("=" * 80)

        report_str = "\n".join(lines)

        # Write output.txt for backward compatibility with EPSS_CVSS_Extract
        try:
            with open("output.txt", "w", encoding="utf-8") as f:
                f.write(report_str)
        except Exception:
            pass

        return {
            "report_text": report_str,
            "matches": matches_data,
            "summary": {
                "bootloader": parsed_info.bootloader_version,
                "kernel": parsed_info.kernel_version,
                "cpu": parsed_info.cpu_raw,
                "arch": parsed_info.cpu_architecture,
                "busybox": parsed_info.busybox_version,
            },
            "cve_count": len(matches_data),
            "severity_breakdown": severity_counts,
            "database": "NIST National Vulnerability Database (NVD 2.0)"
        }

    finally:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception: pass


def find_cve(text: str) -> str:
    """
    Drop-in replacement for find_cve() that routes directly to NIST NVD 2.0 SQLite database.
    """
    res = scan_bootlog_nvd(text)
    return res["report_text"]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        print(find_cve(content))
    else:
        print("Usage: python cv_scanner.py <path_to_bootlog>")
