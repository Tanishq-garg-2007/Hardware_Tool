# generate_answer() / get_vectorstore() / Retrieves top-k relevant excerpts with source metadata.

> 17 nodes · cohesion 0.18

## Key Concepts

- **collect_all_files()** (12 connections) — `Backend/collect_files.py`
- **generate_answer()** (10 connections) — `Backend/ChatBot.py`
- **collect_files.py** (9 connections) — `Backend/collect_files.py`
- **retrieve()** (7 connections) — `Backend/ChatBot.py`
- **get_search_results_json()** (7 connections) — `Backend/collect_files.py`
- **test_rag_pipeline.py** (6 connections) — `Backend/testing_code/test_rag_pipeline.py`
- **run_test()** (5 connections) — `Backend/testing_code/test_rag_pipeline.py`
- **append_file_to_output()** (4 connections) — `Backend/collect_files.py`
- **extract_printable_strings()** (3 connections) — `Backend/collect_files.py`
- **search_in_output()** (3 connections) — `Backend/collect_files.py`
- **get_vectorstore()** (2 connections) — `Backend/ChatBot.py`
- **Retrieves top-k relevant excerpts with source metadata.** (1 connections) — `Backend/ChatBot.py`
- **CLI helper to display search results.** (1 connections) — `Backend/collect_files.py`
- **Safely reads any file (UTF-8, Latin-1, binary, UART serial dump, PDF) and…** (1 connections) — `Backend/collect_files.py`
- **Walks the source folder and concatenates all files into output_file.** (1 connections) — `Backend/collect_files.py`
- **Extracts printable ASCII strings from binary data with noise reduction.** (1 connections) — `Backend/collect_files.py`
- **Searches for occurrences of search_str in output_file with accurate source…** (1 connections) — `Backend/collect_files.py`

## Relationships

- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (11 shared connections)
- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (7 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (5 shared connections)
- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (2 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)

## Source Files

- `Backend/ChatBot.py`
- `Backend/collect_files.py`
- `Backend/testing_code/test_rag_pipeline.py`

## Audit Trail

- EXTRACTED: 49 (98%)
- INFERRED: 1 (2%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*