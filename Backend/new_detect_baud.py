try:
    import serial
except ImportError:
    serial = None

from time import sleep, time
from os import remove, path
import os
import re

try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    GPIO = None

from hardware_config import get_uart_port, OCTOCOUPLER_POWER_PIN

# ---------------- CONFIG ---------------- #
UART_PORT = get_uart_port()
BAUDRATES = [115200, 57600, 38400, 19200, 9600, 4800]
OUTPUT_FILE = "uart_logs/baud_output.txt"

RELAY_PIN = OCTOCOUPLER_POWER_PIN


def init_gpio():
    if GPIO is None:
        return
    try:
        if GPIO.getmode() is None:
            GPIO.setwarnings(False)
            GPIO.setmode(GPIO.BCM)
        try:
            GPIO.setup(RELAY_PIN, GPIO.OUT)
        except Exception:
            pass
    except Exception as e:
        print(f"[WARN] GPIO setup on pin {RELAY_PIN}: {e}")


def switch_power(state):
    if GPIO is None:
        print("[WARN] RPi.GPIO not available. Skipping physical power toggle.")
        return
    init_gpio()

    if state == 0:
        GPIO.output(RELAY_PIN, GPIO.HIGH)   # OFF
    else:
        GPIO.output(RELAY_PIN, GPIO.LOW)    # ON


def evaluate_baud_quality(captured_text: str) -> float:
    """
    Evaluates the quality of captured UART data using generic heuristics:
    1. Printable ASCII ratio (ASCII 32-126 plus \\r, \\n, \\t).
    2. Word token formation (sequences of letters/numbers of length >= 2).
    3. Framing error and null byte penalties.
    4. Character diversity to reject uniform electrical line noise.
    Works for any embedded architecture (U-Boot, Linux, FreeRTOS, ESP, UEFI, bare-metal).
    """
    if not captured_text:
        return 0.0

    clean_text = captured_text.strip("\x00\r\n\t ")
    if len(clean_text) < 10:
        return 0.0

    total_len = len(clean_text)

    # Count valid printable ASCII characters
    printable_count = sum(1 for c in clean_text if (32 <= ord(c) <= 126) or c in "\r\n\t")
    printable_ratio = printable_count / total_len

    # Count null bytes (framing errors / break state)
    null_count = clean_text.count("\x00")
    null_ratio = null_count / total_len

    # If printable ratio is below 60% or null ratio is excessively high, it is framing noise
    if printable_ratio < 0.60 or null_ratio > 0.35 or printable_count < 15:
        return 0.0

    # Check character diversity (reject repetitive line noise like "~~~~~~~" or "UUUUUU")
    unique_chars = len(set(clean_text))
    if unique_chars < 5:
        return 0.0

    # Identify alphanumeric word tokens (length >= 2)
    words = re.findall(r'[a-zA-Z0-9_-]{2,}', clean_text)
    word_count = len(words)
    word_chars = sum(len(w) for w in words)
    word_ratio = word_chars / total_len if total_len > 0 else 0.0

    # Baseline score based on valid character volume and purity
    base_score = printable_count * (printable_ratio ** 2)

    # Word factor bonus (generic for natural language / technical console output)
    word_factor = 1.0 + min(2.0, (word_count * 0.05) + word_ratio)

    # Penalty for nulls/glitches
    null_penalty = max(0.0, 1.0 - (null_ratio * 2))

    final_score = base_score * word_factor * null_penalty
    return round(final_score, 2)


# ---------------- CORE FUNCTION ---------------- #
def check_baud_output(baud_rate, delay, power_delay, power_thread=None):
    print(f"\n[INFO] Testing baud: {baud_rate}")

    if serial is None:
        print("[WARN] pyserial module not available. Returning empty capture.")
        return f"\n\n===== USING {baud_rate} =====\n[WARN: pyserial is not installed or unavailable]\n", ""

    active_port = get_uart_port()

    # Clear any orphaned processes holding the UART device
    if os.name != "nt":
        try:
            os.system(f"fuser -k {active_port} >/dev/null 2>&1")
        except Exception:
            pass

    # Open serial port FIRST before power toggling so driver parameters and baud divisors are initialized cleanly
    try:
        ser = serial.Serial(active_port, baud_rate, timeout=1)
        print(f"[INFO] Serial opened on {active_port} at {baud_rate}")
    except Exception as e:
        print(f"[ERROR] Serial open failed on {active_port}: {e}")
        return f"\n\n===== USING {baud_rate} =====\n[ERROR: Serial open failed on {active_port} - {e}]\n", ""

    sleep(0.2)  # Let UART hardware settle

    # ---------------- POWER OFF ---------------- #
    print(f"[STEP] Powering OFF target for {power_delay}s...")
    switch_power(0)
    sleep(max(1, int(power_delay)))

    # ---------------- POWER ON ---------------- #
    print(f"[STEP] Powering ON target, capturing stream for {delay}s...")
    switch_power(1)

    # ---------------- CAPTURE DATA IMMEDIATELY ---------------- #
    start = time()
    output = f"\n\n===== USING {baud_rate} =====\n"
    actual_captured = ""

    try:
        while time() - start < float(delay):
            data = ser.read(1024)
            if data:
                try:
                    decoded = data.decode("utf-8", errors="ignore")
                    print(decoded, end="", flush=True)
                    output += decoded
                    actual_captured += decoded
                except Exception:
                    pass
            else:
                sleep(0.05)

    except Exception as e:
        print(f"[ERROR] Read error: {e}")
        output += f"\n[Read Error: {e}]\n"

    finally:
        ser.close()
        print(f"\n[INFO] Serial closed for {baud_rate}")

    # ---------------- SAVE OUTPUT ---------------- #
    try:
        with open(OUTPUT_FILE, "a+", encoding="utf-8") as f:
            f.write(output)
    except Exception as e:
        print(f"[ERROR] File write failed: {e}")

    return output, actual_captured


# ---------------- MAIN FUNCTION ---------------- #
def new_run_baud_detection(sampling_time, power_cycle_delay, power_thread=None):
    # Ensure folder exists
    log_dir = path.dirname(OUTPUT_FILE)
    if log_dir and not path.exists(log_dir):
        os.makedirs(log_dir)

    # Remove old file
    try:
        remove(OUTPUT_FILE)
    except Exception:
        pass

    print("\n[INFO] Starting baud detection...\n")

    baud_scores = {}

    # ---------------- TEST ALL BAUDS ---------------- #
    for rate in BAUDRATES:
        output, actual_captured = check_baud_output(
            rate,
            int(sampling_time),
            int(power_cycle_delay),
            power_thread
        )

        score = evaluate_baud_quality(actual_captured)
        baud_scores[rate] = score
        print(f"[INFO] Baud {rate}: {len(actual_captured)} chars captured, quality score: {score:.2f}")

    # Ensure target power remains ON after scan
    switch_power(1)

    # ---------------- EVALUATE BEST BAUD ---------------- #
    best_baud = None
    best_score = 0.0
    for rate, score in baud_scores.items():
        if score > best_score:
            best_score = score
            best_baud = rate

    print("\n===================================")
    if best_baud is not None and best_score > 0.0:
        print(f"[FINAL RESULT] BEST BAUD: {best_baud} (Quality Score: {best_score:.2f})")
        final_summary = f"\n\nFINAL BEST BAUD: {best_baud} (Score: {best_score:.2f})\n"
    else:
        best_baud = None
        print("[FINAL RESULT] None of the tested baudrates produced valid readable UART traffic.")
        final_summary = "\n\nFINAL BEST BAUD: None (No valid UART console traffic detected across any baudrate)\n"
    print("===================================\n")

    # Save final result
    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(final_summary)
    except Exception as e:
        print(f"[ERROR] File write failed: {e}")

    return best_baud
