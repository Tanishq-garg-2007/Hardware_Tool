# analysis() / AnalysisRequest / BootLog

> 12 nodes · cohesion 0.21

## Key Concepts

- **post** (6 connections)
- **process_multiple_files()** (5 connections) — `Backend/useless/main5.py`
- **analysis()** (4 connections) — `Backend/useless/main5.py`
- **chat_with_file()** (4 connections) — `Backend/useless/main5.py`
- **cv_scan()** (4 connections) — `Backend/useless/main5.py`
- **upload_file()** (4 connections) — `Backend/useless/main5.py`
- **AnalysisRequest** (3 connections) — `Backend/useless/main5.py`
- **BootLog** (3 connections) — `Backend/useless/main5.py`
- **ChatRequest** (3 connections) — `Backend/useless/main5.py`
- **BaseModel** (3 connections)
- **summarize()** (3 connections) — `Backend/useless/main5.py`
- **UploadFile** (2 connections)

## Relationships

- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (9 shared connections)
- [generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.](generate_answer_-_get_vectorstore_-_Retrieves_top-k_relevant_excerpts_with_source_metadata.md) (2 shared connections)
- [Agent_Analyze / chunk_text() / extract_deterministic_metadata()](Agent_Analyze_-_chunk_text_-_extract_deterministic_metadata.md) (1 shared connections)
- [cv_scanner / find_cve() / search_keywords_in_files()](cv_scanner_-_find_cve_-_search_keywords_in_files.md) (1 shared connections)
- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (1 shared connections)
- [BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.](BootLog_Summary_-_pre_filter_boot_log_-_Resolves_file_path_with_optional_.txt_extension_and_backend_directory_offsets.md) (1 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (1 shared connections)

## Source Files

- `Backend/useless/main5.py`

## Audit Trail

- EXTRACTED: 30 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*