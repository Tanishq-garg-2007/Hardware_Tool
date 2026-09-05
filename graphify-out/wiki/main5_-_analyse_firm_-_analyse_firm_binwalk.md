# main5 / analyse_firm() / analyse_firm_binwalk()

> 23 nodes · cohesion 0.16

## Key Concepts

- **main5.py** (49 connections) — `Backend/useless/main5.py`
- **get** (19 connections)
- **search_files()** (4 connections) — `Backend/useless/main5.py`
- **cves_endpoint()** (3 connections) — `Backend/useless/main5.py`
- **analyse_firm()** (2 connections) — `Backend/useless/main5.py`
- **analyse_firm_binwalk()** (2 connections) — `Backend/useless/main5.py`
- **baud_detect()** (2 connections) — `Backend/useless/main5.py`
- **boot_log()** (2 connections) — `Backend/useless/main5.py`
- **cap_boot()** (2 connections) — `Backend/useless/main5.py`
- **cap_boot_show()** (2 connections) — `Backend/useless/main5.py`
- **down_firm()** (2 connections) — `Backend/useless/main5.py`
- **dump_firm()** (2 connections) — `Backend/useless/main5.py`
- **getHome()** (2 connections) — `Backend/useless/main5.py`
- **list_all_files()** (2 connections) — `Backend/useless/main5.py`
- **list_devices()** (2 connections) — `Backend/useless/main5.py`
- **list_files()** (2 connections) — `Backend/useless/main5.py`
- **switch_power()** (2 connections) — `Backend/useless/main5.py`
- **uart_console()** (2 connections) — `Backend/useless/main5.py`
- **volt_glitch()** (2 connections) — `Backend/useless/main5.py`
- **volt_glitch_channel()** (2 connections) — `Backend/useless/main5.py`
- **volt_glitch_custom()** (2 connections) — `Backend/useless/main5.py`
- **Returns JSON: { "vulnerabilities": [ { id, baseScore, epssScore,…** (1 connections) — `Backend/useless/main5.py`
- **Endpoint 2: Searches for a string in the already merged file.** (1 connections) — `Backend/useless/main5.py`

## Relationships

- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (9 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (5 shared connections)
- [generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.](generate_answer_-_get_vectorstore_-_Retrieves_top-k_relevant_excerpts_with_source_metadata.md) (5 shared connections)
- [cv_scanner / find_cve() / search_keywords_in_files()](cv_scanner_-_find_cve_-_search_keywords_in_files.md) (2 shared connections)
- [BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.](BootLog_Summary_-_pre_filter_boot_log_-_Resolves_file_path_with_optional_.txt_extension_and_backend_directory_offsets.md) (2 shared connections)
- [Agent_Analyze / chunk_text() / extract_deterministic_metadata()](Agent_Analyze_-_chunk_text_-_extract_deterministic_metadata.md) (2 shared connections)
- [check_default_key / check_default_keys() / main()](check_default_key_-_check_default_keys_-_main.md) (1 shared connections)
- [check_uart_console / check_console() / check_text_for_console()](check_uart_console_-_check_console_-_check_text_for_console.md) (1 shared connections)
- [PowerMod / .__init__() / .run()](PowerMod_-_.__init___-_.run.md) (1 shared connections)
- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (1 shared connections)
- [helper / binwalk_des() / dump_firm_call()](helper_-_binwalk_des_-_dump_firm_call.md) (1 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (1 shared connections)

## Source Files

- `Backend/useless/main5.py`

## Audit Trail

- EXTRACTED: 71 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*