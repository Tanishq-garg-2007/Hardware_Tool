# BootlogInfo / .summary() / _check_bootloader_description()

> 15 nodes · cohesion 0.16

## Key Concepts

- **BootlogInfo** (12 connections) — `Backend/BootLog_Analysis.py`
- **main()** (9 connections) — `Backend/BootLog_Analysis.py`
- **parse_bootlog()** (9 connections) — `Backend/BootLog_Analysis.py`
- **find_cve()** (7 connections) — `Backend/BootLog_Analysis.py`
- **should_update()** (5 connections) — `Backend/BootLog_Analysis.py`
- **generate_json_report()** (4 connections) — `Backend/BootLog_Analysis.py`
- **update()** (4 connections) — `Backend/BootLog_Analysis.py`
- **_check_bootloader_description()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_stream_cve_database()** (3 connections) — `Backend/BootLog_Analysis.py`
- **_classify_architecture()** (2 connections) — `Backend/BootLog_Analysis.py`
- **_extract_cpu_keywords()** (2 connections) — `Backend/BootLog_Analysis.py`
- **parse_args()** (2 connections) — `Backend/BootLog_Analysis.py`
- **_unique_append()** (2 connections) — `Backend/BootLog_Analysis.py`
- **.summary()** (1 connections) — `Backend/BootLog_Analysis.py`
- **Structured representation of parameters extracted from a U-Boot bootlog.** (1 connections) — `Backend/BootLog_Analysis.py`

## Relationships

- [BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()](BootLog_Analysis_-__check_cpu_compatibility_-__check_upstream_downstream_date.md) (21 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (6 shared connections)
- [_bg_red() / _bold() / _c()](_bg_red_-__bold_-__c.md) (3 shared connections)
- [cve_updater / check_should_update() / count_cves()](cve_updater_-_check_should_update_-_count_cves.md) (2 shared connections)

## Source Files

- `Backend/BootLog_Analysis.py`

## Audit Trail

- EXTRACTED: 48 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*