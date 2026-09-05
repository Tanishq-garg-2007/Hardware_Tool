# CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…

> 20 nodes · cohesion 0.17

## Key Concepts

- **scanner_wrapper.py** (15 connections) — `Backend/scanner_wrapper.py`
- **run_scan()** (14 connections) — `Backend/scanner_wrapper.py`
- **get_cvss()** (7 connections) — `Backend/cve_updater.py`
- **EPSS_CVSS_Extract.py** (7 connections) — `Backend/EPSS_CVSS_Extract.py`
- **CVEMatch** (6 connections) — `Backend/BootLog_Analysis.py`
- **_load_cve_database()** (6 connections) — `Backend/BootLog_Analysis.py`
- **compute_vulnerabilities()** (6 connections) — `Backend/EPSS_CVSS_Extract.py`
- **dotenv** (6 connections) — `front/package.json`
- **get_cvss_v2()** (5 connections) — `Backend/EPSS_CVSS_Extract.py`
- **get_epss()** (5 connections) — `Backend/EPSS_CVSS_Extract.py`
- **Any** (4 connections)
- **_serialize_dataclass()** (4 connections) — `Backend/scanner_wrapper.py`
- **extract_cvss_from_vuln()** (3 connections) — `Backend/EPSS_CVSS_Extract.py`
- **Any** (2 connections)
- **dotenv** (2 connections) — `front/package.json`
- **Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…** (1 connections) — `Backend/BootLog_Analysis.py`
- **Represents a CVE that matched the bootlog parameters.** (1 connections) — `Backend/BootLog_Analysis.py`
- **Returns CVSS metrics dictionary for a given CVE ID.** (1 connections) — `Backend/cve_updater.py`
- **Recursively converts dataclasses and sets into JSON-serializable dicts/lists.** (1 connections) — `Backend/scanner_wrapper.py`
- **Executes CVE scan for a single bootlog file OR all bootlog files in a…** (1 connections) — `Backend/scanner_wrapper.py`

## Relationships

- [BootLog_Analysis / _check_cpu_compatibility() / _check_upstream_downstream_date()](BootLog_Analysis_-__check_cpu_compatibility_-__check_upstream_downstream_date.md) (9 shared connections)
- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (6 shared connections)
- [BootlogInfo / .summary() / _check_bootloader_description()](BootlogInfo_-_.summary_-__check_bootloader_description.md) (6 shared connections)
- [cve_updater / check_should_update() / count_cves()](cve_updater_-_check_should_update_-_count_cves.md) (5 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (1 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)
- [assistant_rag / ask_assistant() / get_embeddings()](assistant_rag_-_ask_assistant_-_get_embeddings.md) (1 shared connections)
- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (1 shared connections)
- [axios / bard-ai / bard-ai-google](axios_-_bard-ai_-_bard-ai-google.md) (1 shared connections)

## Source Files

- `Backend/BootLog_Analysis.py`
- `Backend/EPSS_CVSS_Extract.py`
- `Backend/cve_updater.py`
- `Backend/scanner_wrapper.py`
- `front/package.json`

## Audit Trail

- EXTRACTED: 62 (97%)
- INFERRED: 2 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*