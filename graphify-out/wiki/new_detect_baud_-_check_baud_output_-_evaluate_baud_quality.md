# new_detect_baud / check_baud_output() / evaluate_baud_quality()

> 7 nodes · cohesion 0.48

## Key Concepts

- **new_detect_baud.py** (8 connections) — `Backend/new_detect_baud.py`
- **new_run_baud_detection()** (5 connections) — `Backend/new_detect_baud.py`
- **check_baud_output()** (3 connections) — `Backend/new_detect_baud.py`
- **evaluate_baud_quality()** (3 connections) — `Backend/new_detect_baud.py`
- **switch_power()** (3 connections) — `Backend/new_detect_baud.py`
- **init_gpio()** (2 connections) — `Backend/new_detect_baud.py`
- **Evaluates the quality of captured UART data. Returns 0.0 if the output is…** (1 connections) — `Backend/new_detect_baud.py`

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (3 shared connections)
- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (2 shared connections)

## Source Files

- `Backend/new_detect_baud.py`

## Audit Trail

- EXTRACTED: 14 (93%)
- INFERRED: 1 (7%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*