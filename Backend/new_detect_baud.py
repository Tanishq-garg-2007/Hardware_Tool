try:
    import serial
except ImportError:
    serial = None

from time import sleep, time
from os import remove, path
import os
try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None

from hardware_config import get_uart_port, OCTOCOUPLER_POWER_PIN

# ---------------- CONFIG ---------------- #
UART_PORT = get_uart_port()
BAUDRATES = [115200, 9600, 57600, 38400, 19200, 4800]
OUTPUT_FILE = "uart_logs/baud_output.txt"

RELAY_PIN = OCTOCOUPLER_POWER_PIN

def init_gpio():
    if GPIO is None:
        return
    # Initialize only if not already initialized
    if GPIO.getmode() is None:
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)

    # Always ensure the pin is configured as an output
    GPIO.setup(RELAY_PIN, GPIO.OUT, initial=GPIO.HIGH)

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
    Evaluates the quality of captured UART data.
    Returns 0.0 if the output is empty, pure line noise, or lacks valid printable ASCII.
    """
    if not captured_text:
        return 0.0

    stripped = captured_text.strip()
    if len(stripped) < 8:
        return 0.0

    # Count printable characters vs replacement/null/noise
    printable_count = sum(1 for c in stripped if (32 <= ord(c) <= 126) or c in "\r\n\t")
    total_count = len(stripped)

    if total_count == 0:
        return 0.0

    printable_ratio = printable_count / total_count

    # Legitimate UART bootlogs contain at least 65% printable ASCII and at least 15 printable characters
    if printable_count < 15 or printable_ratio < 0.65:
        return 0.0

    # Score combines count of valid characters and clarity ratio
    return printable_count * (printable_ratio ** 2)


# ---------------- CORE FUNCTION ---------------- #
def check_baud_output(baud_rate, delay, power_delay, power_thread):

    print(f"\n[INFO] Testing baud: {baud_rate}")

    # ---------------- POWER OFF ---------------- #
    print("[STEP] POWER OFF")
    switch_power(0)
    sleep(power_delay)

    # ---------------- OPEN SERIAL BEFORE POWER ON ---------------- #
    if serial is None:
        print("[WARN] pyserial module not available. Returning empty capture.")
        return f"\n\n===== USING {baud_rate} =====\n[WARN: pyserial is not installed or unavailable]\n", ""

    try:
        ser = serial.Serial(UART_PORT, baud_rate, timeout=1)
        print(f"[INFO] Serial testing at {baud_rate}")
    except Exception as e:
        print(f"[ERROR] Serial open failed: {e}")
        return f"\n\n===== USING {baud_rate} =====\n[ERROR: Serial open failed - {e}]\n", ""

    # ---------------- POWER ON ---------------- #
    print("[STEP] POWER ON")
    switch_power(1)

    # ---------------- CAPTURE DATA ---------------- #
    start = time()
    output = f"\n\n===== USING {baud_rate} =====\n"
    actual_captured = ""

    try:
        while True:
            end = time()

            received_data = ser.read(1)
            sleep(0.03)
            received_data += ser.read(ser.in_waiting)

            if received_data:
                try:
                    decoded = received_data.decode("utf-8", errors="ignore")
                    print(decoded, end="")   # PRINT LIVE OUTPUT
                    output += decoded       # SAVE OUTPUT
                    actual_captured += decoded
                except Exception:
                    pass

            if end - start > delay:
                break

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
def new_run_baud_detection(sampling_time, power_cycle_delay, power_thread):

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
        print(f"[INFO] Baud {rate}: {len(actual_captured)} chars captured, quality score: {score:.1f}")

    # ---------------- FIND BEST BAUD ---------------- #
    best_baud = None
    best_score = 0.0
    for rate, score in baud_scores.items():
        if score > best_score:
            best_score = score
            best_baud = rate

    print("\n===================================")
    if best_baud is not None and best_score > 0.0:
        print(f"[FINAL RESULT] Baudrate Operating on this device is: {best_baud} (Quality Score: {best_score:.1f})")
        final_summary = f"\n\nFINAL BEST BAUD: {best_baud}\n"
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
