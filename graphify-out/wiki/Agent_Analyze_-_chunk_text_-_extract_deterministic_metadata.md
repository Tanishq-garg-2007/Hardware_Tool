# Agent_Analyze / chunk_text() / extract_deterministic_metadata()

> 12 nodes · cohesion 0.24

## Key Concepts

- **run()** (9 connections) — `Backend/Agent_Analyze.py`
- **Agent_Analyze.py** (8 connections) — `Backend/Agent_Analyze.py`
- **load_and_clean_file()** (4 connections) — `Backend/Agent_Analyze.py`
- **chunk_text()** (3 connections) — `Backend/Agent_Analyze.py`
- **extract_deterministic_metadata()** (3 connections) — `Backend/Agent_Analyze.py`
- **extract_strings_from_binary()** (3 connections) — `Backend/Agent_Analyze.py`
- **filter_relevant_strings()** (3 connections) — `Backend/Agent_Analyze.py`
- **Backwards-compatible wrapper that returns extracted lines.** (1 connections) — `Backend/Agent_Analyze.py`
- **Applies regex filtering to keep only lines matching task-specific keywords.…** (1 connections) — `Backend/Agent_Analyze.py`
- **Splits filtered text into manageable chunks and caps the total chunk count.** (1 connections) — `Backend/Agent_Analyze.py`
- **High-speed (<5ms) deterministic regex & pattern extractor. Extracts structured…** (1 connections) — `Backend/Agent_Analyze.py`
- **Intelligently reads either plain-text files (bootlogs, scripts) or raw binary…** (1 connections) — `Backend/Agent_Analyze.py`

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (2 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (2 shared connections)
- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (1 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)

## Source Files

- `Backend/Agent_Analyze.py`

## Audit Trail

- EXTRACTED: 21 (95%)
- INFERRED: 1 (5%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*