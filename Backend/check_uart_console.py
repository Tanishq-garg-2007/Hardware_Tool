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
    "dram",
    "board:",
    "kernel",
    "setting cal",
    "pll init",
    "pll_init",
    "autoboot",
    "hit any key",
]

COMMON_SYSTEM_WORDS = {
    "init", "boot", "kernel", "version", "device", "memory", "system", "start", "done", "ready",
    "load", "image", "flash", "chip", "freq", "clock", "timer", "cpu", "mhz", "ghz", "ram", "rom",
    "dram", "ddr", "uart", "serial", "console", "baud", "rate", "ok", "fail", "error", "warn",
    "info", "debug", "root", "login", "password", "user", "addr", "size", "total", "dev", "eth",
    "mac", "net", "board", "linux", "uboot", "u-boot", "busybox", "shell", "press", "enter",
    "stop", "autoboot", "gpio", "spi", "reg", "val", "set", "cfg", "pll", "div", "irq",
    "status", "config", "reset", "read", "write", "crc", "magic", "header", "block", "sector",
    "cpm", "pdiv", "h2div", "cdiv", "cppcr", "cpapcr", "cpmpcr", "hit", "any", "key", "delay",
    "seconds", "bytes", "loading", "starting", "uncompressing", "command", "prompt", "openwrt",
    "welcome", "relocation", "offset", "physical", "nand", "nor", "spi"
}


def toggle_target_power(state: int, power_thread=None):
    """
    Safely toggles target power state (0 = OFF, 1 = ON) in Relay mode.
    Directly drives RELAY_POWER_PIN (LOW = OFF, HIGH = ON) and synchronizes
    OCTOCOUPLER_POWER_PIN (HIGH = OFF, LOW = ON) as well as power_thread.
    """
    try:
        from hardware_config import get_gpio, RELAY_POWER_PIN, OCTOCOUPLER_POWER_PIN
        gpio = get_gpio()
        if gpio is not None:
            if gpio.getmode() is None:
                gpio.setwarnings(False)
                gpio.setmode(gpio.BCM)
            try:
                gpio.setup(RELAY_POWER_PIN, gpio.OUT)
                val = gpio.LOW if state == 0 else gpio.HIGH
                gpio.output(RELAY_POWER_PIN, val)
            except Exception:
                pass
            try:
                gpio.setup(OCTOCOUPLER_POWER_PIN, gpio.OUT)
                octo_val = gpio.HIGH if state == 0 else gpio.LOW
                gpio.output(OCTOCOUPLER_POWER_PIN, octo_val)
            except Exception:
                pass
    except Exception as e:
        print(f"[WARN] Direct GPIO toggle failed: {e}")

    # Synchronize power_thread if available
    if power_thread is not None and hasattr(power_thread, "set_state"):
        try:
            power_thread.set_state(state)
        except Exception:
            pass


def switch_octocoupler_power(state: int, power_thread=None):
    """
    Safely toggles target power state (0 = OFF, 1 = ON) in Octocoupler mode.
    Drives OCTOCOUPLER_POWER_PIN (0 = HIGH, 1 = LOW) AND synchronizes
    RELAY_POWER_PIN (0 = LOW, 1 = HIGH) via power_thread so that whether
    the target device is powered via the optical switch or electromechanical relay,
    it reboots and initializes reliably.
    """
    try:
        from hardware_config import get_gpio, OCTOCOUPLER_POWER_PIN, RELAY_POWER_PIN
        gpio = get_gpio()
        if gpio is not None:
            if gpio.getmode() is None:
                gpio.setwarnings(False)
                gpio.setmode(gpio.BCM)
            try:
                gpio.setup(OCTOCOUPLER_POWER_PIN, gpio.OUT)
                val = gpio.HIGH if state == 0 else gpio.LOW
                gpio.output(OCTOCOUPLER_POWER_PIN, val)
            except Exception:
                pass
            try:
                gpio.setup(RELAY_POWER_PIN, gpio.OUT)
                relay_val = gpio.LOW if state == 0 else gpio.HIGH
                gpio.output(RELAY_POWER_PIN, relay_val)
            except Exception:
                pass
    except Exception as e:
        print(f"[WARN] Octocoupler power toggle failed: {e}")

    # Synchronize power_thread if available
    if power_thread is not None and hasattr(power_thread, "set_state"):
        try:
            power_thread.set_state(state)
        except Exception:
            pass


def is_garbage_text(content: str) -> bool:
    """
    Detects if the received UART content is framing noise / garbage resulting from
    an incorrect baudrate (e.g. 115200 device sampled at 9600) or electrical distortion.
    """
    if not content:
        return False

    # Immediate check for null-only noise
    if content.count("\x00") >= 5 and not content.strip("\x00\r\n\t "):
        return True

    clean = content.strip("\x00\r\n\t ")
    total = len(clean)
    if total == 0:
        return False

    # 1. Non-ASCII check: bytes > 127 (e.g. ¶, ¿, framing error MSB shifts)
    non_ascii_count = sum(1 for c in clean if ord(c) > 127)
    if non_ascii_count > 0 and (non_ascii_count / total) >= 0.01:
        return True

    # 2. Control chars / nulls check
    null_count = content.count("\x00")
    if total > 0 and (null_count / (total + null_count)) > 0.15:
        return True

    # 3. Framing noise symbol bursts (e.g. "+*::, `%, [$, @\, }`%)
    symbol_clusters = re.findall(r"[\"!@#$%^&*`~|\\+<>[\]{}]{2,}", clean)
    noisy_clusters = [c for c in symbol_clusters if not re.match(r"^(=+|-+|\*+|\.+|>+|<+|/{2,})$", c)]
    if len(noisy_clusters) >= 2 or any(len(c) >= 3 for c in noisy_clusters):
        return True

    # 4. Long tokens filled with random symbols (e.g. Qq#8PYU%Y2DA@qQ4!C`A#YA1OQZXQU[$YUQ1XUYxYQt&Qq>6Y)
    tokens = clean.split()
    for tok in tokens:
        if len(tok) > 20 and not re.match(r"^[0-9a-fA-F_xX]+$", tok):
            syms = sum(1 for c in tok if c in "\"!@#$%^&*`~|\\+=<>[\]{}")
            if syms >= 2:
                return True

    # 5. High symbol ratio across the whole text (random unformatted punctuation)
    symbols_total = sum(1 for c in clean if (32 <= ord(c) <= 126) and not c.isalnum() and c not in " \t\r\n:=,.-_()[]/\"")
    if total >= 20 and (symbols_total / total) >= 0.12:
        return True

    # 6. Repetitive line noise (e.g. ~~~~~~~ or UUUUUUU)
    if len(set(clean)) < 4 and total >= 10:
        return True

    # 7. Check words: if text has word-like tokens, check if they are gibberish
    words = re.findall(r"\b[a-zA-Z]{3,}\b", clean.lower())
    if len(words) >= 2:
        recognized = sum(1 for w in words if w in COMMON_SYSTEM_WORDS or any(sw in w for sw in COMMON_SYSTEM_WORDS))
        if recognized == 0:
            abnormal = sum(1 for w in words if re.search(r"[qxzj]{2,}", w) or re.search(r"([bcdfghjklmnpqrstvwxz])\1\1", w))
            if abnormal > 0 or len(noisy_clusters) > 0:
                return True

    return False


def evaluate_baud_quality(captured_text: str) -> float:
    """
    Evaluates the quality of captured UART data using generic heuristics.
    Returns 0.0 immediately if the content is identified as framing noise.
    """
    if not captured_text:
        return 0.0

    if is_garbage_text(captured_text):
        return 0.0

    clean_text = captured_text.strip("\x00\r\n\t ")
    if len(clean_text) < 10:
        return 0.0

    total_len = len(clean_text)
    printable_count = sum(1 for c in clean_text if (32 <= ord(c) <= 126) or c in "\r\n\t")
    printable_ratio = printable_count / total_len
    null_count = clean_text.count("\x00")
    null_ratio = null_count / total_len

    if printable_ratio < 0.70 or null_ratio > 0.20 or printable_count < 15:
        return 0.0

    unique_chars = len(set(clean_text))
    if unique_chars < 5:
        return 0.0

    words = re.findall(r"\b[a-zA-Z0-9_-]{2,}\b", clean_text)
    word_count = len(words)
    word_chars = sum(len(w) for w in words)
    word_ratio = word_chars / total_len if total_len > 0 else 0.0

    recognized = sum(1 for w in words if w.lower() in COMMON_SYSTEM_WORDS or any(sw in w.lower() for sw in COMMON_SYSTEM_WORDS))

    base_score = printable_count * (printable_ratio ** 2)
    word_factor = 1.0 + min(2.5, (word_count * 0.05) + word_ratio + (recognized * 0.25))
    null_penalty = max(0.0, 1.0 - (null_ratio * 3))

    return round(base_score * word_factor * null_penalty, 2)


def check_text_for_console(content: str) -> tuple:
    """
    Checks if genuine console prompts, shell indicators, or readable UART
    traffic are present.
    Returns: (is_available: bool, is_garbage: bool)
    """
    if not content:
        return False, False

    clean = content.strip("\x00\r\n\t ")
    if not clean:
        if is_garbage_text(content):
            return False, True
        return False, False

    lowered = clean.lower()

    # Ignore trivial short error messages from hardware or python
    if ("[error]" in lowered or "[warn]" in lowered) and len(content.strip().splitlines()) <= 2:
        return False, False

    # 1. PRIORITY 1: Check if content is framing noise / garbage FIRST!
    if is_garbage_text(content):
        return False, True

    # 2. Check for explicit genuine console / boot triggers
    for trigger in CONSOLE_TRIGGERS:
        if len(trigger) <= 4 and trigger.isalpha():
            if re.search(r"\b" + re.escape(trigger) + r"\b", lowered):
                return True, False
        else:
            if trigger in lowered:
                return True, False

    # 3. Check for shell prompt endings like root@...# or user@...$ or =>
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    for line in lines[-5:]:
        if (
            line.endswith("#") or line.endswith("$") or line.endswith("=>") or line.endswith(">")
        ) and any(c.isalnum() for c in line):
            return True, False

    # 4. Check if text is genuine readable console stream with substantial quality score
    if evaluate_baud_quality(content) >= 60.0:
        return True, False

    return False, False


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
    Powers cycles the target, opens the UART port, captures the boot stream,
    and returns (success, output, error_message).
    """
    if serial is None:
        return False, "", "pyserial library is not installed or unavailable on this system."

    from hardware_config import get_uart_port
    active_port = get_uart_port()

    # Clear any orphaned processes holding the UART device
    if os.name != "nt":
        try:
            os.system(f"fuser -k {active_port} >/dev/null 2>&1")
        except Exception:
            pass

    # Open serial port FIRST before power toggling
    try:
        ser = serial.Serial(active_port, baud_rate, timeout=0.1)
        print(f"[INFO] Serial opened on {active_port} at {baud_rate}")
    except Exception as e:
        print(f"[ERROR] Serial open failed on {active_port}: {e}")
        return False, "", f"Unable to open serial port {active_port}: {str(e)}"

    time.sleep(0.2)  # Let UART hardware settle

    def set_power(st):
        if mode == "octocoupler":
            switch_octocoupler_power(st, power_thread)
        else:
            toggle_target_power(st, power_thread)

    # ---------------- POWER OFF ---------------- #
    print(f"[STEP] Powering OFF target for {power_delay}s (mode={mode})...")
    set_power(0)
    time.sleep(max(1, int(power_delay)))

    # ---------------- POWER ON ---------------- #
    print(f"[STEP] Powering ON target, capturing stream for {listen_time}s...")
    set_power(1)

    # ---------------- CAPTURE DATA IMMEDIATELY ---------------- #
    start = time.time()
    output = ""

    try:
        while time.time() - start < float(listen_time):
            waiting = ser.in_waiting
            if waiting:
                data = ser.read(waiting)
                if data:
                    try:
                        decoded = data.decode("utf-8", errors="ignore")
                        print(decoded, end="", flush=True)
                        output += decoded
                    except Exception:
                        pass
            time.sleep(0.03)

        # Wake the console if device is already at an interactive shell prompt
        if attempt_uboot_breakout:
            ser.write(b"\r\n")
            ser.flush()
            post_start = time.time()
            while time.time() - post_start < 1.0:
                waiting = ser.in_waiting
                if waiting:
                    data = ser.read(waiting)
                    if data:
                        try:
                            decoded = data.decode("utf-8", errors="ignore")
                            print(decoded, end="", flush=True)
                            output += decoded
                        except Exception:
                            pass
                time.sleep(0.03)

    except Exception as e:
        print(f"[ERROR] Read error during console check: {e}")
        return False, output, f"Error communicating during console check: {str(e)}"

    finally:
        ser.close()
        print(f"\n[INFO] Serial closed for {baud_rate}")
        # Ensure target remains powered on
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

    is_avail, is_garbage = check_text_for_console(output)

    if is_avail:
        return {
            "success": True,
            "is_available": True,
            "is_garbage": False,
            "status": "console is available",
            "data": "console is available",
            "message": "Interactive UART Console / Boot Output Detected",
            "log": output
        }
    elif is_garbage:
        return {
            "success": True,
            "is_available": False,
            "is_garbage": True,
            "status": "garbage_detected",
            "data": "garbage_detected",
            "message": f"Garbage serial data detected at {baud_rate} baud (framing noise).",
            "log": output
        }
    else:
        return {
            "success": True,
            "is_available": False,
            "is_garbage": False,
            "status": "console is not available",
            "data": "console is not available",
            "message": f"No interactive console prompt detected at {baud_rate} baud.",
            "log": output or "No response from device"
        }
