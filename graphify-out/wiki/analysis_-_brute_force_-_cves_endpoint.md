# analysis() / brute_force() / cves_endpoint()

> 14 nodes · cohesion 0.20

## Key Concepts

- **post** (16 connections)
- **new_cves_endpoint()** (6 connections) — `Backend/main.py`
- **scan_firmware()** (6 connections) — `Backend/main.py`
- **cves_endpoint()** (5 connections) — `Backend/main.py`
- **process_multiple_files()** (5 connections) — `Backend/main.py`
- **UploadFile** (5 connections)
- **analysis()** (4 connections) — `Backend/main.py`
- **brute_force()** (4 connections) — `Backend/main.py`
- **ScanResponse** (3 connections) — `Backend/main.py`
- **upload_file()** (3 connections) — `Backend/main.py`
- **Request** (2 connections)
- **Accepts a bootlog file from the frontend, saves it temporarily, and passes it…** (1 connections) — `Backend/main.py`
- **Accepts a bootlog file from the frontend, saves it temporarily, and passes it…** (1 connections) — `Backend/main.py`
- **Accepts target directory_path or an uploaded file (binary/archive/system file),…** (1 connections) — `Backend/main.py`

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (15 shared connections)
- [assistant_rag / ask_assistant() / get_embeddings()](assistant_rag_-_ask_assistant_-_get_embeddings.md) (2 shared connections)
- [Agent_Analyze / chunk_text() / extract_deterministic_metadata()](Agent_Analyze_-_chunk_text_-_extract_deterministic_metadata.md) (1 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (1 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (1 shared connections)
- [cv_scanner_40_new / _bg_red() / _bold()](cv_scanner_40_new_-__bg_red_-__bold.md) (1 shared connections)
- [EPSS_CVSS_Extract_new / compute_vulnerabilities1() / get_epss()](EPSS_CVSS_Extract_new_-_compute_vulnerabilities1_-_get_epss.md) (1 shared connections)
- [generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.](generate_answer_-_get_vectorstore_-_Retrieves_top-k_relevant_excerpts_with_source_metadata.md) (1 shared connections)
- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (1 shared connections)
- [BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.](BootLog_Summary_-_pre_filter_boot_log_-_Resolves_file_path_with_optional_.txt_extension_and_backend_directory_offsets.md) (1 shared connections)
- [Hardcoded_Password / FirmwareScanner / .detect_hash_type()](Hardcoded_Password_-_FirmwareScanner_-_.detect_hash_type.md) (1 shared connections)

## Source Files

- `Backend/main.py`

## Audit Trail

- EXTRACTED: 41 (93%)
- INFERRED: 3 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*