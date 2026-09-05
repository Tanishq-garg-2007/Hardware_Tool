# bruteforce_uart / check_login() / main()

> 29 nodes · cohesion 0.11

## Key Concepts

- **hardware_config.py** (16 connections) — `Backend/hardware_config.py`
- **get_uart_port()** (16 connections) — `Backend/hardware_config.py`
- **capture_uart_boot.py** (8 connections) — `Backend/capture_uart_boot.py`
- **check_login()** (7 connections) — `Backend/bruteforce_uart.py`
- **detect_baud.py** (7 connections) — `Backend/detect_baud.py`
- **bruteforce_uart.py** (6 connections) — `Backend/bruteforce_uart.py`
- **get_hardware_diagnostics()** (5 connections) — `Backend/hardware_config.py`
- **power_module.py** (5 connections) — `Backend/power_module.py`
- **list_bin_uart.py** (5 connections) — `Backend/useless/list_bin_uart.py`
- **get_gpio()** (4 connections) — `Backend/hardware_config.py`
- **capture_boot_output()** (3 connections) — `Backend/capture_uart_boot.py`
- **evaluate_baud_quality()** (3 connections) — `Backend/detect_baud.py`
- **run_baud_detection()** (3 connections) — `Backend/detect_baud.py`
- **check_bins()** (3 connections) — `Backend/useless/list_bin_uart.py`
- **main()** (3 connections) — `Backend/useless/list_bin_uart.py`
- **main()** (2 connections) — `Backend/bruteforce_uart.py`
- **main()** (2 connections) — `Backend/capture_uart_boot.py`
- **check_baud_output()** (2 connections) — `Backend/detect_baud.py`
- **get_slm_thread_count()** (2 connections) — `Backend/hardware_config.py`
- **is_raspberry_pi_5()** (2 connections) — `Backend/hardware_config.py`
- **check_log_for_bin()** (2 connections) — `Backend/useless/list_bin_uart.py`
- **force_relay_toggle()** (1 connections) — `Backend/capture_uart_boot.py`
- **Evaluates the quality of captured UART data. Returns 0.0 if the output is…** (1 connections) — `Backend/detect_baud.py`
- **MockRPi** (1 connections) — `Backend/hardware_config.py`
- **Calculates optimal thread allocation for local SLM/LLM inference.** (1 connections) — `Backend/hardware_config.py`
- *... and 4 more nodes in this community*

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (10 shared connections)
- [main5 / analyse_firm() / analyse_firm_binwalk()](main5_-_analyse_firm_-_analyse_firm_binwalk.md) (5 shared connections)
- [new_capture_uart_boot / force_relay_toggle() / init_gpio()](new_capture_uart_boot_-_force_relay_toggle_-_init_gpio.md) (3 shared connections)
- [new_detect_baud / check_baud_output() / evaluate_baud_quality()](new_detect_baud_-_check_baud_output_-_evaluate_baud_quality.md) (2 shared connections)
- [check_uart_console / check_console() / check_text_for_console()](check_uart_console_-_check_console_-_check_text_for_console.md) (2 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (1 shared connections)
- [analysis() / AnalysisRequest / BootLog](analysis_-_AnalysisRequest_-_BootLog.md) (1 shared connections)
- [MockGPIO / .output() / .setmode()](MockGPIO_-_.output_-_.setmode.md) (1 shared connections)
- [ChatBot / check_and_purge_expired_index() / clean_log_text()](ChatBot_-_check_and_purge_expired_index_-_clean_log_text.md) (1 shared connections)
- [MockGPIO / .cleanup() / .getmode()](MockGPIO_-_.cleanup_-_.getmode.md) (1 shared connections)
- [PowerMod / .__init__() / .run()](PowerMod_-_.__init___-_.run.md) (1 shared connections)

## Source Files

- `Backend/bruteforce_uart.py`
- `Backend/capture_uart_boot.py`
- `Backend/detect_baud.py`
- `Backend/hardware_config.py`
- `Backend/power_module.py`
- `Backend/useless/list_bin_uart.py`

## Audit Trail

- EXTRACTED: 71 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*