# ChatBot / check_and_purge_expired_index() / clean_log_text()

> 17 nodes · cohesion 0.24

## Key Concepts

- **reindex_database()** (16 connections) — `Backend/ChatBot.py`
- **ChatBot.py** (12 connections) — `Backend/ChatBot.py`
- **test_retention_and_cache.py** (9 connections) — `Backend/testing_code/test_retention_and_cache.py`
- **check_and_purge_expired_index()** (8 connections) — `Backend/ChatBot.py`
- **test_retention_and_caching()** (8 connections) — `Backend/testing_code/test_retention_and_cache.py`
- **get_index_metadata()** (6 connections) — `Backend/ChatBot.py`
- **safe_delete_path()** (6 connections) — `Backend/ChatBot.py`
- **save_index_metadata()** (5 connections) — `Backend/ChatBot.py`
- **clean_log_text()** (3 connections) — `Backend/ChatBot.py`
- **compute_file_hash()** (3 connections) — `Backend/ChatBot.py`
- **Computes SHA-256 hash of a file for content-based cache invalidation.** (1 connections) — `Backend/ChatBot.py`
- **Reads index metadata containing timestamps, expiration, and content hash.** (1 connections) — `Backend/ChatBot.py`
- **Saves index metadata with UTC timestamps.** (1 connections) — `Backend/ChatBot.py`
- **Checks if the indexed files have exceeded the 30-day retention window. If…** (1 connections) — `Backend/ChatBot.py`
- **Manages vector index lifecycle: 1. Checks if existing index is within 30 days…** (1 connections) — `Backend/ChatBot.py`
- **Compresses consecutive identical lines (e.g. spammy UART polling / retry lines)…** (1 connections) — `Backend/ChatBot.py`
- **Safely deletes a file or directory. If PermissionError occurs (e.g. root/sudo…** (1 connections) — `Backend/ChatBot.py`

## Relationships

- [generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.](generate_answer_-_get_vectorstore_-_Retrieves_top-k_relevant_excerpts_with_source_metadata.md) (11 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (1 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (1 shared connections)
- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (1 shared connections)
- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (1 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (1 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)

## Source Files

- `Backend/ChatBot.py`
- `Backend/testing_code/test_retention_and_cache.py`

## Audit Trail

- EXTRACTED: 49 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*