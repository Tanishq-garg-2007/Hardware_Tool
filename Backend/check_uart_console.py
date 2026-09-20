try:
    import serial
    import serial.serialutil
except ImportError:
    serial = None

import time
import os
import re

OUTPUT_FILE = "uart_logs/uart_console_log.txt"

CONSOLE_TRIGGERS = [
    "login:",
    "username:",
    "password:",
    "root@",
    "busybox",
    "sh-",
    "bash-",
    "=>",
    "# ",
    "$ ",
    "shell",
    "press enter",
    "u-boot",
    "uboot",
    "/bin/sh",
    "linux version",
    "booting",
    "console",
    "apsoc",
    "mips",
    "arm",
]


def toggle_target_power(state: int, power_thread=None):
    """
    Safely toggles target power state (0 = OFF, 1 = ON) in Relay mode.
    Directly drives RELAY_POWER_PIN (LOW = OFF, HIGH = ON) matching detect_baud.py.
    """
    try:
        from hardware_config import get_gpio, RELAY_POWER_PIN
        gpio = get_gpio()
        if gpio is not None:
            if gpio.getmode() is None:
                gpio.setwarnings(False)
                gpio.setmode(gpio.BCM)
            try:
                gpio.setup(RELAY_POWER_PIN, gpio.OUT)
            except Exception:
                pass
            val = gpio.LOW if state == 0 else gpio.HIGH
            gpio.output(RELAY_POWER_PIN, val)
    except Exception as e:
        print(f"[WARN] Direct GPIO toggle failed: {e}")

    # Synchronize power_thread if available
    if power_thread is not None and hasattr(power_thread, "set_state"):
        try:
            power_thread.set_state(state)
        except Exception:
            pass


def switch_octocoupler_power(state: int):
    """
    Safely toggles target power state (0 = OFF, 1 = ON) in Octocoupler mode.
    Active LOW: 0 = OFF (HIGH), 1 = ON (LOW).
    """
    try:
        from hardware_config import get_gpio, OCTOCOUPLER_POWER_PIN
        gpio = get_gpio()
        if gpio is not None:
            if gpio.getmode() is None:
                gpio.setwarnings(False)
                gpio.setmode(gpio.BCM)
            try:
                gpio.setup(OCTOCOUPLER_POWER_PIN, gpio.OUT)
            except Exception:
                pass
            val = gpio.HIGH if state == 0 else gpio.LOW
            gpio.output(OCTOCOUPLER_POWER_PIN, val)
    except Exception as e:
        print(f"[WARN] Octocoupler power toggle failed: {e}")


def evaluate_baud_quality(captured_text: str) -> float:
    """
    Evaluates the quality of captured UART data using generic heuristics
    matching detect_baud.py.
    """
    if not captured_text:
        return 0.0

    clean_text = captured_text.strip("\x00\r\n\t ")
    if len(clean_text) < 10:
        return 0.0

    total_len = len(clean_text)
    printable_count = sum(1 for c in clean_text if (32 <= ord(c) <= 126) or c in "\r\n\t")
    printable_ratio = printable_count / total_len
    null_count = clean_text.count("\x00")
    null_ratio = null_count / total_len

    if printable_ratio < 0.60 or null_ratio > 0.35 or printable_count < 15:
        return 0.0

    unique_chars = len(set(clean_text))
    if unique_chars < 5:
        return 0.0

    words = re.findall(r'[a-zA-Z0-9_-]{2,}', clean_text)
    word_count = len(words)
    word_chars = sum(len(w) for w in words)
    word_ratio = word_chars / total_len if total_len > 0 else 0.0

    base_score = printable_count * (printable_ratio ** 2)
    word_factor = 1.0 + min(2.0, (word_count * 0.05) + word_ratio)
    null_penalty = max(0.0, 1.0 - (null_ratio * 2))

    return round(base_score * word_factor * null_penalty, 2)


def check_text_for_console(content: str) -> bool:
    """
    Checks if genuine console prompts, shell indicators, or readable UART
    traffic are present.
    """
    if not content:
        return False

    lowered = content.lower()

    # Ignore trivial short error messages
    if ("[error]" in lowered or "[warn]" in lowered) and len(content.strip().splitlines()) <= 2:
        return False

    for trigger in CONSOLE_TRIGGERS:
        if trigger in lowered:
            return True

    # Check for shell prompt endings like root@...# or user@...$ or =>
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    for line in lines[-5:]:
        if line.endswith("#") or line.endswith("$") or line.endswith("=>"):
            return True

    # Check if text is genuine readable console stream
    if evaluate_baud_quality(content) > 0.0:
        return True

    return False


def check_console(
    baud_rate: int,
    power_thread=None,
    power_delay: int = 3,
    listen_time: int = 5,
    mode: str = "relay",
    attempt_uboot_breakout: bool = True,
    **kwargs
):
    """
    Uses the exact same timing and capture logic as detect_baud.py:
    1. Clear any orphaned processes holding the UART port with fuser -k.
    2. Open serial port FIRST before power toggling so baud divisors and hardware line
       parameters are initialized cleanly.
    3. Settle for 0.2s.
    4. Power OFF target for power_delay (default 3s).
    5. Power ON target.
    6. Capture data immediately for listen_time (default 5s) using 1024-byte reads.
    7. Close serial and guarantee power remains ON.
    """
    if serial is None:
        return False, "", "pyserial library is not installed or unavailable on this system."

    from hardware_config import get_uart_port
    active_port = get_uart_port()

    # Clear any orphaned processes holding the UART device (same as detect_baud.py)
    if os.name != "nt":
        try:
            os.system(f"fuser -k {active_port} >/dev/null 2>&1")
        except Exception:
            pass

    # Open serial port FIRST before power toggling (same as detect_baud.py)
    try:
        ser = serial.Serial(active_port, baud_rate, timeout=1)
        print(f"[INFO] Serial opened on {active_port} at {baud_rate}")
    except Exception as e:
        print(f"[ERROR] Serial open failed on {active_port}: {e}")
        return False, "", f"Unable to open serial port {active_port}: {str(e)}"

    time.sleep(0.2)  # Let UART hardware settle

    def set_power(st):
        if mode == "octocoupler":
            switch_octocoupler_power(st)
        else:
            toggle_target_power(st, power_thread)

    # ---------------- POWER OFF ---------------- #
    print(f"[STEP] Powering OFF target for {power_delay}s (mode={mode})...")
    set_power(0)
    time.sleep(max(1, int(power_delay)))

    # ---------------- POWER ON ---------------- #
    print(f"[STEP] Powering ON target, capturing stream for {listen_time}s...")
    set_power(1)

    # ---------------- CAPTURE DATA IMMEDIATELY (same as detect_baud.py) ---------------- #
    start = time.time()
    output = ""

    try:
        while time.time() - start < float(listen_time):
            data = ser.read(1024)
            if data:
                try:
                    decoded = data.decode("utf-8", errors="ignore")
                    print(decoded, end="", flush=True)
                    output += decoded
                except Exception:
                    pass
            else:
                time.sleep(0.05)

    except Exception as e:
        print(f"[ERROR] Read error during console check: {e}")
        return False, output, f"Error communicating during console check: {str(e)}"

    finally:
        ser.close()
        print(f"\n[INFO] Serial closed for {baud_rate}")
        # Ensure target remains powered on (same as detect_baud.py)
        set_power(1)

    return True, output, None


def main(
    baud_rate: int,
    power_thread=None,
    power_delay: int = 3,
    listen_time: int = 5,
    mode: str = "relay",
    attempt_uboot_breakout: bool = True,
    **kwargs
) -> dict:
    os.makedirs("uart_logs", exist_ok=True)

    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except Exception:
            pass

    success, output, error_msg = check_console(
        baud_rate=int(baud_rate),
        power_thread=power_thread,
        power_delay=int(power_delay),
        listen_time=int(listen_time),
        mode=mode,
        attempt_uboot_breakout=bool(attempt_uboot_breakout),
        **kwargs
    )

    # Save log to file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        if success:
            f.write(output or "[No serial traffic received]")
        else:
            f.write(f"[Hardware Error]: {error_msg}\n{output}")

    if not success:
        return {
            "success": False,
            "is_available": False,
            "status": "error",
            "message": error_msg,
            "data": f"Error: {error_msg}",
            "log": error_msg
        }

    is_avail = check_text_for_console(output)

    if is_avail:
        return {
            "success": True,
            "is_available": True,
            "status": "console is available",
            "data": "console is available",
            "message": "Interactive UART Console / Boot Output Detected",
            "log": output
        }
    else:
        return {
            "success": True,
            "is_available": False,
            "status": "console is not available",
            "data": "console is not available",
            "message": "No interactive console prompt detected at this baudrate",
            "log": output or "No response from device"
        }
