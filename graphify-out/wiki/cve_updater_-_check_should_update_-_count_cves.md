# cve_updater / check_should_update() / count_cves()

> 22 nodes · cohesion 0.20

## Key Concepts

- **cve_updater.py** (15 connections) — `Backend/cve_updater.py`
- **get_nvd_db_path()** (12 connections) — `Backend/cve_updater.py`
- **check_should_update()** (9 connections) — `Backend/cve_updater.py`
- **_download_and_extract_task()** (9 connections) — `Backend/cve_updater.py`
- **get_database_status()** (8 connections) — `Backend/cve_updater.py`
- **get_cve_db_dir()** (7 connections) — `Backend/cve_updater.py`
- **trigger_database_update()** (7 connections) — `Backend/cve_updater.py`
- **count_cves()** (6 connections) — `Backend/cve_updater.py`
- **Path** (6 connections)
- **query_firmware_cves()** (5 connections) — `Backend/cve_updater.py`
- **get_cve_by_id()** (4 connections) — `Backend/cve_updater.py`
- **_extract_metrics()** (3 connections) — `Backend/cve_updater.py`
- **init_nvd_sqlite()** (3 connections) — `Backend/cve_updater.py`
- **query_cves_by_product()** (3 connections) — `Backend/cve_updater.py`
- **_stream_cve_items()** (3 connections) — `Backend/cve_updater.py`
- **Extracts (base_score, severity, version, vector) from NVD 2.0 metrics block.…** (1 connections) — `Backend/cve_updater.py`
- **Memory-efficient streaming parser for NVD JSON format. Yields individual CVE…** (1 connections) — `Backend/cve_updater.py`
- **Ensures tables and indexes exist in the NVD database.** (1 connections) — `Backend/cve_updater.py`
- **Fetches a single CVE from the local NVD SQLite store in < 1ms.** (1 connections) — `Backend/cve_updater.py`
- **Fetches all CVEs matching a vendor and product from the NVD database.** (1 connections) — `Backend/cve_updater.py`
- **Fetches all CVEs matching any (vendor, product) pair in product_pairs. Used by…** (1 connections) — `Backend/cve_updater.py`
- **Returns the total number of indexed CVEs in the SQLite database.** (1 connections) — `Backend/cve_updater.py`

## Relationships

- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (5 shared connections)
- [BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()](BootLog_Analysis_-__check_cpu_compatibility_-__check_upstream_downstream_date.md) (4 shared connections)
- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (4 shared connections)
- [BootlogInfo / .summary() / _check_bootloader_description()](BootlogInfo_-_.summary_-__check_bootloader_description.md) (2 shared connections)

## Source Files

- `Backend/cve_updater.py`

## Audit Trail

- EXTRACTED: 60 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*