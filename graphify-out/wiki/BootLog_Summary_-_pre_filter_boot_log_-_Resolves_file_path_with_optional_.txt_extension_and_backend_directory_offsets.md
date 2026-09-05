# BootLog_Summary / pre_filter_boot_log() / Resolves file path with optional .txt extension and backend directory offsets.

> 7 nodes · cohesion 0.43

## Key Concepts

- **summarize_boot_log()** (7 connections) — `Backend/BootLog_Summary.py`
- **BootLog_Summary.py** (5 connections) — `Backend/BootLog_Summary.py`
- **pre_filter_boot_log()** (4 connections) — `Backend/BootLog_Summary.py`
- **resolve_bootlog_path()** (4 connections) — `Backend/BootLog_Summary.py`
- **summarize()** (3 connections) — `Backend/main.py`
- **Resolves file path with optional .txt extension and backend directory offsets.** (1 connections) — `Backend/BootLog_Summary.py`
- **Blazing fast pre-filtering with Python regex: - Eliminates 95% of benign boot…** (1 connections) — `Backend/BootLog_Summary.py`

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (3 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (2 shared connections)
- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (1 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)

## Source Files

- `Backend/BootLog_Summary.py`
- `Backend/main.py`

## Audit Trail

- EXTRACTED: 16 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*