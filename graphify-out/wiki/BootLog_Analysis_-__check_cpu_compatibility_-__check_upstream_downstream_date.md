# BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()

> 29 nodes · cohesion 0.16

## Key Concepts

- **BootLog_Analysis.py** (64 connections) — `Backend/BootLog_Analysis.py`
- **scan_kernel_cves()** (23 connections) — `Backend/BootLog_Analysis.py`
- **scan_bootloader_cves()** (22 connections) — `Backend/BootLog_Analysis.py`
- **_check_cpu_compatibility()** (5 connections) — `Backend/BootLog_Analysis.py`
- **_get_cpe_matches()** (5 connections) — `Backend/BootLog_Analysis.py`
- **compare_versions()** (4 connections) — `Backend/BootLog_Analysis.py`
- **_format_version_range()** (4 connections) — `Backend/BootLog_Analysis.py`
- **_get_description()** (4 connections) — `Backend/BootLog_Analysis.py`
- **is_version_in_range()** (4 connections) — `Backend/BootLog_Analysis.py`
- **_check_upstream_downstream_date()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_get_cve_obj()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_get_references()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_get_severity_and_score()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_get_weaknesses()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_normalize_version_string()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_parse_version_tuple()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_sort_cves()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_sync_get_id()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_sync_get_last_modified()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_sync_get_published()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_detect_arch_in_text()** (2 connections) — `Backend/BootLog_Analysis.py`
- **_extract_fallback_version()** (2 connections) — `Backend/BootLog_Analysis.py`
- **extract_version_from_cpe()** (2 connections) — `Backend/BootLog_Analysis.py`
- **_is_kernel_branch_mismatch()** (2 connections) — `Backend/BootLog_Analysis.py`
- **extract_target_hw_from_cpe()** (1 connections) — `Backend/BootLog_Analysis.py`
- *... and 4 more nodes in this community*

## Relationships

- [BootlogInfo / .summary() / _check_bootloader_description()](BootlogInfo_-_.summary_-__check_bootloader_description.md) (21 shared connections)
- [_bg_red() / _bold() / _c()](_bg_red_-__bold_-__c.md) (14 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (9 shared connections)
- [cve_updater / check_should_update() / count_cves()](cve_updater_-_check_should_update_-_count_cves.md) (4 shared connections)
- [detect_kernel_subsystem() / _lookup_commit_prefix() / Map a raw commit-subject prefix to a bootlog subsystem name, or None.](detect_kernel_subsystem_-__lookup_commit_prefix_-_Map_a_raw_commit-subject_prefix_to_a_bootlog_subsystem_name,_or_None.md) (3 shared connections)

## Source Files

- `Backend/BootLog_Analysis.py`

## Audit Trail

- EXTRACTED: 116 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*