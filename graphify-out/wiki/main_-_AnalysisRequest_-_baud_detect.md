# main / AnalysisRequest / baud_detect()

> 45 nodes · cohesion 0.08

## Key Concepts

- **main.py** (97 connections) — `Backend/main.py`
- **get** (17 connections)
- **BaseModel** (14 connections)
- **search_files()** (5 connections) — `Backend/main.py`
- **chat_with_file()** (4 connections) — `Backend/main.py`
- **cve_database_update()** (4 connections) — `Backend/main.py`
- **hardware_info()** (4 connections) — `Backend/main.py`
- **scan_path_endpoint()** (4 connections) — `Backend/main.py`
- **BootLog** (3 connections) — `Backend/main.py`
- **BootlogScanPathRequest** (3 connections) — `Backend/main.py`
- **ChatRequest** (3 connections) — `Backend/main.py`
- **ChipRequest** (3 connections) — `Backend/main.py`
- **cv_scan()** (3 connections) — `Backend/main.py`
- **cve_database_status()** (3 connections) — `Backend/main.py`
- **CveUpdateRequest** (3 connections) — `Backend/main.py`
- **detect_chip_name()** (3 connections) — `Backend/main.py`
- **extract_firmware()** (3 connections) — `Backend/main.py`
- **FlashRequest** (3 connections) — `Backend/main.py`
- **new_baud_detect()** (3 connections) — `Backend/main.py`
- **new_capture_boot()** (3 connections) — `Backend/main.py`
- **new_volt_glitch_custom()** (3 connections) — `Backend/main.py`
- **startup()** (3 connections) — `Backend/main.py`
- **AnalysisRequest** (2 connections) — `Backend/main.py`
- **baud_detect()** (2 connections) — `Backend/main.py`
- **capture_boot()** (2 connections) — `Backend/main.py`
- *... and 20 more nodes in this community*

## Relationships

- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (15 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (10 shared connections)
- [generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.](generate_answer_-_get_vectorstore_-_Retrieves_top-k_relevant_excerpts_with_source_metadata.md) (7 shared connections)
- [assistant_rag / ask_assistant() / get_embeddings()](assistant_rag_-_ask_assistant_-_get_embeddings.md) (7 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (6 shared connections)
- [cve_updater / check_should_update() / count_cves()](cve_updater_-_check_should_update_-_count_cves.md) (4 shared connections)
- [BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.](BootLog_Summary_-_pre_filter_boot_log_-_Resolves_file_path_with_optional_.txt_extension_and_backend_directory_offsets.md) (3 shared connections)
- [new_capture_uart_boot / force_relay_toggle() / init_gpio()](new_capture_uart_boot_-_force_relay_toggle_-_init_gpio.md) (3 shared connections)
- [new_detect_baud / check_baud_output() / evaluate_baud_quality()](new_detect_baud_-_check_baud_output_-_evaluate_baud_quality.md) (3 shared connections)
- [cv_scanner / find_cve() / search_keywords_in_files()](cv_scanner_-_find_cve_-_search_keywords_in_files.md) (2 shared connections)
- [PowerMod / .__init__() / .run()](PowerMod_-_.__init___-_.run.md) (2 shared connections)
- [Agent_Analyze / chunk_text() / extract_deterministic_metadata()](Agent_Analyze_-_chunk_text_-_extract_deterministic_metadata.md) (2 shared connections)

## Source Files

- `Backend/main.py`

## Audit Trail

- EXTRACTED: 151 (97%)
- INFERRED: 4 (3%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*