try:
    import serial
except ImportError:
    serial = None

from time import sleep, time
import os
from datetime import datetime

try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    class MockGPIO:
        BCM = "BCM"
        OUT = "OUT"
        HIGH = 1
        LOW = 0
        def setwarnings(self, flag): pass
        def setmode(self, mode): pass
        def setup(self, pin, mode, initial=None): pass
        def output(self, pin, val): pass
    GPIO = MockGPIO()

from hardware_config import get_uart_port, RELAY_POWER_PIN

# ---------------- CONFIG ---------------- #
UART_PORT = get_uart_port()
RELAY_PIN = RELAY_POWER_PIN
OUTPUT_FILE = "uart_logs/uart_boot_log.txt"

# ---------------- GPIO SETUP ---------------- #
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(RELAY_PIN, GPIO.OUT, initial=GPIO.HIGH)


# ---------------- RELAY CONTROL ---------------- #
def force_relay_toggle(power_delay):
    print("[INFO] Toggling relay...")
    # Power OFF
    GPIO.output(RELAY_PIN, GPIO.LOW)
    sleep(power_delay)
    # Power ON
    GPIO.output(RELAY_PIN, GPIO.HIGH)
    sleep(0.1)


# ---------------- CORE FUNCTION ---------------- #
def capture_boot_output(baud_rate, delay, power_delay):
    if serial is None:
        return "[ERROR] pyserial module is not installed or unavailable on this system."

    port = get_uart_port()
    if os.name != "nt":
        try:
            os.system(f"fuser -k {port} >/dev/null 2>&1")
        except Exception:
            pass

    print(f"[STEP] Opening UART FIRST on {port}")
    try:
        ser = serial.Serial(port, baud_rate, timeout=1)
    except Exception as e:
        print(f"[ERROR] Failed to open serial port {port}: {e}")
        return f"[ERROR] Failed to open serial port {port}: {e}"

    sleep(0.2)   # let UART settle

    print("[STEP] POWER OFF")
    GPIO.output(6, GPIO.LOW)
    sleep(power_delay)

    print("[STEP] POWER ON")
    GPIO.output(6, GPIO.HIGH)

    print("[STEP] START READING IMMEDIATELY")

    start = time()
    output = ""

    try:
        while time() - start < delay:
            data = ser.read(1024)
            if data:
                decoded = data.decode("utf-8", errors="ignore")
                print(decoded, end="")
                output += decoded
            else:
                sleep(0.05)
    except Exception as e:
        output += f"\n[ERROR during capture: {e}]\n"
    finally:
        ser.close()

    return output

# ---------------- MAIN ENTRY ---------------- #
def main(baud_rate, sampling_time, power_cycle_delay):
    print(f"[INFO] Starting UART boot capture at {baud_rate} baud...")
    output = capture_boot_output(
        int(baud_rate),
        int(sampling_time),
        int(power_cycle_delay)
    )
    print("[INFO] UART boot capture complete.")
    return output
