# check_uart_console / check_console() / check_text_for_console()

> 6 nodes · cohesion 0.47

## Key Concepts

- **check_uart_console.py** (6 connections) — `Backend/check_uart_console.py`
- **check_console()** (4 connections) — `Backend/check_uart_console.py`
- **check_text_for_console()** (3 connections) — `Backend/check_uart_console.py`
- **main()** (3 connections) — `Backend/check_uart_console.py`
- **Checks if genuine console prompts or shell indicators are present. Explicitly…** (1 connections) — `Backend/check_uart_console.py`
- **Powers cycles the target, opens the UART port, sends CRLF to prompt for shell,…** (1 connections) — `Backend/check_uart_console.py`

## Relationships

- [bruteforce_uart / check_login() / main()](bruteforce_uart_-_check_login_-_main.md) (2 shared connections)
- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (1 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (1 shared connections)

## Source Files

- `Backend/check_uart_console.py`

## Audit Trail

- EXTRACTED: 11 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*