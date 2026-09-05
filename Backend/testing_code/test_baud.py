import serial
import time
import RPi.GPIO as GPIO
import os


# ============================================================
# CONFIG
# ============================================================

UART_PORT = "/dev/serial0"

RELAY_PIN = 6

BAUDRATES = [

    115200
    
]

CAPTURE_TIME = 8
POWER_OFF_TIME = 3


# ============================================================
# GPIO SETUP
# ============================================================

GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)

GPIO.setup(
    RELAY_PIN,
    GPIO.OUT,
    initial=GPIO.LOW
)


# ============================================================
# RELAY FUNCTIONS
# ============================================================

def power_off():
    print("[RELAY] OFF")
    GPIO.output(RELAY_PIN, GPIO.LOW)


def power_on():
    print("[RELAY] ON")
    GPIO.output(RELAY_PIN, GPIO.HIGH)


# ============================================================
# BAUD TEST
# ============================================================

def test_baud(baud):

    print()
    print("=" * 70)
    print(f"[BAUD TEST] {baud}")
    print("=" * 70)

    ser = None

    # --------------------------------------------------------
    # POWER OFF
    # --------------------------------------------------------

    print("[STEP] Power OFF target")

    power_off()

    time.sleep(POWER_OFF_TIME)


    # --------------------------------------------------------
    # OPEN UART BEFORE POWER ON
    # --------------------------------------------------------

    try:

        print(
            f"[STEP] Opening {UART_PORT} @ {baud}"
        )

        ser = serial.Serial(
            port=UART_PORT,
            baudrate=baud,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=0.05
        )

        print(
            f"[OK] UART opened @ {baud}"
        )

        ser.reset_input_buffer()

    except Exception as e:

        print(
            f"[ERROR] UART open failed: {e}"
        )

        return {
            "baud": baud,
            "bytes": 0,
            "data": b""
        }


    # --------------------------------------------------------
    # POWER ON
    # --------------------------------------------------------

    print("[STEP] Power ON target")

    power_on()

    # Allow relay contacts to settle
    time.sleep(0.05)


    # --------------------------------------------------------
    # CAPTURE
    # --------------------------------------------------------

    print()
    print(
        f"[CAPTURE] Capturing for {CAPTURE_TIME} seconds..."
    )

    print("-" * 70)

    start = time.monotonic()

    received = bytearray()

    while time.monotonic() - start < CAPTURE_TIME:

        try:

            data = ser.read(
                ser.in_waiting or 1
            )

            if data:

                received.extend(data)

                # LIVE OUTPUT
                print(
                    data.decode(
                        "utf-8",
                        errors="replace"
                    ),
                    end="",
                    flush=True
                )

        except Exception as e:

            print(
                f"\n[ERROR] UART read: {e}"
            )

            break

        time.sleep(0.002)


    # --------------------------------------------------------
    # CLOSE UART
    # --------------------------------------------------------

    ser.close()

    print()
    print(
        f"[INFO] UART closed @ {baud}"
    )


    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    data = bytes(received)

    print()
    print(
        f"[RESULT] Baud  : {baud}"
    )

    print(
        f"[RESULT] Bytes : {len(data)}"
    )

    return {
        "baud": baud,
        "bytes": len(data),
        "data": data
    }


# ============================================================
# MAIN
# ============================================================

results = []


try:

    print()
    print("=" * 70)
    print("          RASPBERRY PI 5 AUTOMATIC UART DETECTION")
    print("=" * 70)

    print(
        f"UART       : {UART_PORT}"
    )

    print(
        f"RELAY GPIO : BCM {RELAY_PIN}"
    )

    print(
        f"BAUD RATES : {BAUDRATES}"
    )

    print(
        f"CAPTURE    : {CAPTURE_TIME}s"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # TEST EACH BAUD
    # --------------------------------------------------------

    for baud in BAUDRATES:

        result = test_baud(baud)

        results.append(result)


        # Always power OFF between tests
        power_off()

        time.sleep(1)


finally:

    # --------------------------------------------------------
    # SAFETY
    # --------------------------------------------------------

    print()
    print("[STEP] Power OFF target")

    power_off()

    GPIO.cleanup()


# ============================================================
# RESULTS
# ============================================================

print()
print()
print("=" * 80)
print("                         RESULTS")
print("=" * 80)

print(
    f"{'BAUD':>10} {'BYTES':>10}"
)

print("-" * 80)

for r in results:

    print(
        f"{r['baud']:>10} "
        f"{r['bytes']:>10}"
    )


# ============================================================
# BEST BAUD
# ============================================================

if results:

    best = max(
        results,
        key=lambda x: x["bytes"]
    )

    print()
    print("=" * 80)
    print(
        f"[FINAL RESULT] BEST BAUD = {best['baud']}"
    )
    print(
        f"[FINAL RESULT] BYTES     = {best['bytes']}"
    )
    print("=" * 80)

    if best["bytes"] == 0:

        print()
        print(
            "[WARNING] No UART data received."
        )

        print(
            "[WARNING] This is NOT a baud-rate problem."
        )

        print(
            "[WARNING] Check camera TX -> Pi GPIO15."
        )

    else:

        print()
        print(
            "[SUCCESS] UART DATA DETECTED"
        )
