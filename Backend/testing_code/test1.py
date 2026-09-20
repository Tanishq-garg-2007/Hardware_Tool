#!/usr/bin/env python3

import os
import sys
import glob
import time

# ============================================================
# IMPORT UART
# ============================================================

try:
    import serial
except ImportError:
    print("ERROR: pyserial is not installed.")
    print("Install with:")
    print("sudo apt install python3-serial")
    sys.exit(1)


# ============================================================
# IMPORT GPIO
# ============================================================

try:
    import RPi.GPIO as GPIO
except ImportError:
    print("ERROR: RPi.GPIO is not available.")
    sys.exit(1)


# ============================================================
# CONFIGURATION
# ============================================================

RELAY_PIN = 6                  # BCM 6
RELAY_PHYSICAL_PIN = 31

# Change these if your relay is ACTIVE LOW
RELAY_ON = GPIO.HIGH
RELAY_OFF = GPIO.LOW

BAUD_RATES = [
    9600,
    19200,
    38400,
    57600,
    115200,
    230400,
    460800,
    921600,
]

POWER_OFF_TIME = 2
BOOT_CAPTURE_TIME = 5
PROMPT_CAPTURE_TIME = 2
BETWEEN_TESTS = 1

LOG_DIR = "uart_logs"
LOG_FILE = os.path.join(
    LOG_DIR,
    "independent_uart_baud.log"
)


# ============================================================
# GPIO FUNCTIONS
# ============================================================

def gpio_init():

    print()
    print("[GPIO] Initializing relay...")

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)

    try:

        GPIO.setup(
            RELAY_PIN,
            GPIO.OUT,
            initial=RELAY_OFF
        )

    except Exception as e:

        print(
            f"[GPIO ERROR] BCM {RELAY_PIN} is busy "
            f"or cannot be claimed."
        )

        print(f"[GPIO ERROR] {e}")

        raise

    print(
        f"[GPIO] BCM {RELAY_PIN} "
        f"(Physical Pin {RELAY_PHYSICAL_PIN}) initialized"
    )

    print("[GPIO] Relay initially OFF")


def relay_on():

    GPIO.output(
        RELAY_PIN,
        RELAY_ON
    )

    print(
        f"[RELAY] ON "
        f"(BCM {RELAY_PIN}, Physical {RELAY_PHYSICAL_PIN})"
    )


def relay_off():

    try:

        GPIO.output(
            RELAY_PIN,
            RELAY_OFF
        )

        print(
            f"[RELAY] OFF "
            f"(BCM {RELAY_PIN}, Physical {RELAY_PHYSICAL_PIN})"
        )

    except Exception as e:

        print(
            f"[RELAY] Unable to turn OFF: {e}"
        )


def gpio_cleanup():

    print()
    print("[GPIO] Starting cleanup...")

    try:

        # Make absolutely sure target power is OFF
        GPIO.output(
            RELAY_PIN,
            RELAY_OFF
        )

        print("[GPIO] Relay OFF")

    except Exception as e:

        print(
            f"[GPIO] Could not set relay OFF: {e}"
        )

    try:

        GPIO.cleanup(RELAY_PIN)

        print(
            f"[GPIO] BCM {RELAY_PIN} released"
        )

    except Exception as e:

        print(
            f"[GPIO] Cleanup error: {e}"
        )

    print("[GPIO] Cleanup complete")


# ============================================================
# UART PORT DETECTION
# ============================================================

def get_uart_port():

    # Explicit port supplied by user
    custom_port = os.getenv("UART_PORT")

    if custom_port:

        print(
            f"[UART] Using UART_PORT={custom_port}"
        )

        return custom_port

    # Pi 5 GPIO UART
    candidates = [
        "/dev/serial0",
        "/dev/ttyAMA0",
        "/dev/ttyAMA10",
        "/dev/ttyS0",
    ]

    for port in candidates:

        if os.path.exists(port):

            return port

    # USB UART
    usb_ports = sorted(
        glob.glob("/dev/ttyUSB*") +
        glob.glob("/dev/ttyACM*")
    )

    for port in usb_ports:

        if os.path.exists(port):

            return port

    return None


# ============================================================
# UART CAPTURE
# ============================================================

def capture_uart(ser, duration):

    received = bytearray()

    start = time.time()

    while (time.time() - start) < duration:

        waiting = ser.in_waiting

        if waiting > 0:

            data = ser.read(waiting)

            received.extend(data)

            decoded = data.decode(
                "utf-8",
                errors="replace"
            )

            print(
                decoded,
                end="",
                flush=True
            )

        time.sleep(0.02)

    return bytes(received)


# ============================================================
# CONSOLE DETECTION
# ============================================================

CONSOLE_TRIGGERS = [
    "login:",
    "username:",
    "password:",
    "root@",
    "busybox",
    "sh-",
    "bash-",
    "u-boot",
    "booting",
    "kernel",
    "linux",
    "shell",
    "press enter",
    "=>",
    "/bin/sh",
]


def detect_console(text):

    if not text:

        return False

    lowered = text.lower()

    for trigger in CONSOLE_TRIGGERS:

        if trigger in lowered:

            return True

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    for line in lines[-10:]:

        if line.endswith("#"):
            return True

        if line.endswith("$"):
            return True

        if line.endswith("=>"):
            return True

    return False


# ============================================================
# UART DATA QUALITY
# ============================================================

def calculate_quality(text):

    if not text:

        return 0.0

    printable = 0

    for character in text:

        value = ord(character)

        if (
            value == 9 or
            value == 10 or
            value == 13 or
            32 <= value <= 126
        ):

            printable += 1

    return printable / len(text)


# ============================================================
# TEST ONE BAUD RATE
# ============================================================

def test_baud(port, baud):

    print()
    print("=" * 70)
    print(f"TESTING BAUD RATE: {baud}")
    print("=" * 70)

    ser = None
    received = bytearray()

    try:

        # ----------------------------------------------------
        # 1. TARGET POWER OFF
        # ----------------------------------------------------

        relay_off()

        print(
            f"[POWER] OFF for {POWER_OFF_TIME} seconds"
        )

        time.sleep(POWER_OFF_TIME)

        # ----------------------------------------------------
        # 2. OPEN UART BEFORE POWER ON
        # ----------------------------------------------------

        print(
            f"[UART] Opening {port} @ {baud}"
        )

        ser = serial.Serial(
            port=port,
            baudrate=baud,
            timeout=0.1,
            write_timeout=1,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE
        )

        ser.reset_input_buffer()
        ser.reset_output_buffer()

        print("[UART] Port opened")

        # ----------------------------------------------------
        # 3. POWER ON TARGET
        # ----------------------------------------------------

        relay_on()

        # ----------------------------------------------------
        # 4. CAPTURE BOOTLOG
        # ----------------------------------------------------

        print()
        print(
            f"[UART] Capturing bootlog "
            f"for {BOOT_CAPTURE_TIME} seconds..."
        )

        data = capture_uart(
            ser,
            BOOT_CAPTURE_TIME
        )

        received.extend(data)

        # ----------------------------------------------------
        # 5. SEND CRLF
        # ----------------------------------------------------

        print()
        print("[UART] Sending CRLF")

        ser.write(b"\r\n")
        ser.flush()

        # ----------------------------------------------------
        # 6. CAPTURE RESPONSE
        # ----------------------------------------------------

        data = capture_uart(
            ser,
            PROMPT_CAPTURE_TIME
        )

        received.extend(data)

        # ----------------------------------------------------
        # 7. ANALYZE
        # ----------------------------------------------------

        text = received.decode(
            "utf-8",
            errors="replace"
        )

        quality = calculate_quality(text)

        console = detect_console(text)

        score = 0

        if len(received) > 0:
            score += 1

        if len(received) >= 20:
            score += 1

        if quality >= 0.70:
            score += 2

        if quality >= 0.90:
            score += 1

        if console:
            score += 5

        if score >= 6:

            status = "STRONG MATCH"

        elif score >= 3:

            status = "POSSIBLE MATCH"

        else:

            status = "NO CLEAR MATCH"

        print()
        print("-" * 70)

        print(
            f"Baud rate      : {baud}"
        )

        print(
            f"Bytes received : {len(received)}"
        )

        print(
            f"Text quality   : {quality * 100:.1f}%"
        )

        print(
            f"Console found  : {console}"
        )

        print(
            f"Score          : {score}/10"
        )

        print(
            f"Result         : {status}"
        )

        return {
            "baud": baud,
            "bytes": len(received),
            "quality": quality,
            "console": console,
            "score": score,
            "status": status,
            "data": text,
        }

    except Exception as e:

        print()
        print(
            f"[UART ERROR] {e}"
        )

        return {
            "baud": baud,
            "bytes": 0,
            "quality": 0,
            "console": False,
            "score": 0,
            "status": "ERROR",
            "data": "",
        }

    finally:

        # ----------------------------------------------------
        # CLOSE UART
        # ----------------------------------------------------

        if ser is not None:

            try:

                ser.close()

                print(
                    "[UART] Port closed"
                )

            except Exception:
                pass

        # ----------------------------------------------------
        # POWER OFF BEFORE NEXT BAUD
        # ----------------------------------------------------

        relay_off()

        time.sleep(BETWEEN_TESTS)


# ============================================================
# MAIN
# ============================================================

def main():

    os.makedirs(
        LOG_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # GET UART
    # --------------------------------------------------------

    port = get_uart_port()

    if port is None:

        print(
            "[ERROR] No UART device found."
        )

        return 1

    print()
    print("=" * 70)
    print("       INDEPENDENT UART BAUD RATE DETECTOR")
    print("=" * 70)

    print()
    print(
        f"UART port        : {port}"
    )

    print(
        f"Real device      : {os.path.realpath(port)}"
    )

    print(
        f"Relay BCM        : {RELAY_PIN}"
    )

    print(
        f"Relay physical   : Pin {RELAY_PHYSICAL_PIN}"
    )

    # --------------------------------------------------------
    # GPIO INITIALIZATION
    # --------------------------------------------------------

    gpio_init()

    results = []

    try:

        # ----------------------------------------------------
        # INITIAL TARGET POWER OFF
        # ----------------------------------------------------

        relay_off()

        time.sleep(POWER_OFF_TIME)

        # ----------------------------------------------------
        # TEST ALL BAUD RATES
        # ----------------------------------------------------

        for baud in BAUD_RATES:

            result = test_baud(
                port,
                baud
            )

            results.append(result)

    except KeyboardInterrupt:

        print()
        print("[!] Test interrupted by user.")

    except Exception as e:

        print()
        print(
            f"[MAIN ERROR] {e}"
        )

    finally:

        # ----------------------------------------------------
        # CRITICAL CLEANUP
        # ----------------------------------------------------

        gpio_cleanup()

    # ========================================================
    # FINAL RESULTS
    # ========================================================

    print()
    print()
    print("=" * 80)
    print("                         FINAL RESULTS")
    print("=" * 80)

    print()

    print(
        f"{'BAUD':>10} "
        f"{'BYTES':>8} "
        f"{'QUALITY':>10} "
        f"{'CONSOLE':>10} "
        f"{'SCORE':>8} "
        f"STATUS"
    )

    print("-" * 80)

    results.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    for result in results:

        print(
            f"{result['baud']:>10} "
            f"{result['bytes']:>8} "
            f"{result['quality'] * 100:>9.1f}% "
            f"{str(result['console']):>10} "
            f"{result['score']:>8} "
            f"{result['status']}"
        )

    # ========================================================
    # BEST BAUD RATE
    # ========================================================

    if results:

        best = results[0]

        print()
        print("=" * 80)

        if best["score"] >= 6:

            print(
                f"DETECTED BAUD RATE: {best['baud']}"
            )

        else:

            print(
                "NO RELIABLE BAUD RATE DETECTED"
            )

        print("=" * 80)

    # ========================================================
    # SAVE LOG
    # ========================================================

    with open(
        LOG_FILE,
        "w",
        encoding="utf-8",
        errors="replace"
    ) as log:

        log.write(
            "INDEPENDENT UART BAUD RATE DETECTION\n"
        )

        log.write(
            f"UART PORT: {port}\n"
        )

        log.write(
            f"REAL DEVICE: {os.path.realpath(port)}\n"
        )

        log.write(
            f"RELAY: BCM {RELAY_PIN} / "
            f"PHYSICAL PIN {RELAY_PHYSICAL_PIN}\n"
        )

        log.write(
            "=" * 80 + "\n\n"
        )

        for result in results:

            log.write(
                f"BAUD RATE: {result['baud']}\n"
            )

            log.write(
                f"BYTES: {result['bytes']}\n"
            )

            log.write(
                f"QUALITY: "
                f"{result['quality'] * 100:.1f}%\n"
            )

            log.write(
                f"CONSOLE: {result['console']}\n"
            )

            log.write(
                f"SCORE: {result['score']}/10\n"
            )

            log.write(
                f"STATUS: {result['status']}\n"
            )

            log.write(
                "-" * 80 + "\n"
            )

            log.write(
                result["data"]
            )

            log.write(
                "\n\n"
            )

    print()
    print(
        f"Log saved to: {os.path.abspath(LOG_FILE)}"
    )

    return 0


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    sys.exit(main())
