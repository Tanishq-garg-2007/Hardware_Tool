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
        def getmode(self): return "BCM"
    GPIO = MockGPIO()

from hardware_config import get_uart_port, OCTOCOUPLER_POWER_PIN

# ---------------- CONFIG ---------------- #
UART_PORT = get_uart_port()
OUTPUT_FILE = "uart_logs/uart_boot_log.txt"

RELAY_PIN = OCTOCOUPLER_POWER_PIN

def init_gpio():
    if GPIO is None:
        return
    if GPIO.getmode() is None:
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
    GPIO.setup(RELAY_PIN, GPIO.OUT, initial=GPIO.HIGH)

def switch_power(state):
    if GPIO is None:
        return
    init_gpio()
    if state == 0:
        GPIO.output(RELAY_PIN, GPIO.HIGH)   # OFF (Octocoupler)
    else:
        GPIO.output(RELAY_PIN, GPIO.LOW)    # ON (Octocoupler)

    try:
        from hardware_config import RELAY_POWER_PIN
        GPIO.setup(RELAY_POWER_PIN, GPIO.OUT)
        GPIO.output(RELAY_POWER_PIN, GPIO.LOW if state == 0 else GPIO.HIGH)
    except Exception:
        pass

# ---------------- RELAY CONTROL ---------------- #
def force_relay_toggle(power_delay):
    print("[INFO] Toggling relay...")
    switch_power(0)
    sleep(power_delay)
    switch_power(1)
    sleep(0.1)


# ---------------- CORE FUNCTION ---------------- #
def new_capture_boot_output(baud_rate, delay, power_delay):
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

    sleep(0.2)

    # ---------------- POWER OFF ----------------
    print("[STEP] POWER OFF")
    switch_power(0)
    sleep(power_delay)

    # ---------------- POWER ON -----------------
    print("[STEP] POWER ON")
    switch_power(1)

    print("[STEP] START READING IMMEDIATELY")

    start = time()
    output = ""

    try:
        while time() - start < delay:
            if ser.in_waiting:
                data = ser.read(ser.in_waiting)
                try:
                    decoded = data.decode("utf-8", errors="ignore")
                    print(decoded, end="")
                    output += decoded
                except Exception:
                    pass
            sleep(0.03)
    except Exception as e:
        output += f"\n[ERROR during capture: {e}]\n"
    finally:
        ser.close()

    return output

# ---------------- MAIN ENTRY ---------------- #
def main(baud_rate, sampling_time, power_cycle_delay):
    print(f"[INFO] Starting UART boot capture at {baud_rate} baud...")
    output = new_capture_boot_output(
        int(baud_rate),
        int(sampling_time),
        int(power_cycle_delay)
    )
    print("[INFO] UART boot capture complete.")
    return output
