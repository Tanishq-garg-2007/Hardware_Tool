import serial
import time
import RPi.GPIO as GPIO


# ============================================================
# CONFIGURATION
# ============================================================

UART_PORT = "/dev/ttyAMA0"

RELAY_PIN = 6

BAUDRATE = 115200

POWER_OFF_DELAY = 3
CAPTURE_TIME = 20


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
# MAIN TEST
# ============================================================

ser = None

try:

    print("=" * 70)
    print("             RASPBERRY PI 5 UART TEST")
    print("=" * 70)

    print(f"UART       : {UART_PORT}")
    print(f"BAUD       : {BAUDRATE}")
    print(f"RELAY GPIO : BCM {RELAY_PIN}")
    print()

    # --------------------------------------------------------
    # POWER OFF
    # --------------------------------------------------------

    print("[1] POWER OFF CAMERA")

    GPIO.output(
        RELAY_PIN,
        GPIO.LOW
    )

    time.sleep(POWER_OFF_DELAY)


    # --------------------------------------------------------
    # OPEN UART
    # --------------------------------------------------------

    print("[2] OPENING UART")

    ser = serial.Serial(
        port=UART_PORT,
        baudrate=BAUDRATE,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.05
    )

    print("[OK] UART OPEN")

    # Clear any stale data
    ser.reset_input_buffer()

    print("[OK] UART BUFFER CLEARED")


    # --------------------------------------------------------
    # POWER ON
    # --------------------------------------------------------

    print()
    print("[3] POWER ON CAMERA")

    GPIO.output(
        RELAY_PIN,
        GPIO.HIGH
    )

    # Give relay contact time to settle
    time.sleep(0.05)

    print("[OK] CAMERA POWER ON")


    # --------------------------------------------------------
    # CAPTURE
    # --------------------------------------------------------

    print()
    print(
        f"[4] CAPTURING UART FOR {CAPTURE_TIME} SECONDS"
    )

    print("-" * 70)

    start = time.monotonic()

    total_bytes = 0

    while time.monotonic() - start < CAPTURE_TIME:

        waiting = ser.in_waiting

        if waiting > 0:

            data = ser.read(waiting)

            if data:

                total_bytes += len(data)

                # Raw output
                print(
                    data.decode(
                        "utf-8",
                        errors="replace"
                    ),
                    end="",
                    flush=True
                )

        else:

            # Still wait for incoming data
            data = ser.read(1)

            if data:

                total_bytes += len(data)

                print(
                    data.decode(
                        "utf-8",
                        errors="replace"
                    ),
                    end="",
                    flush=True
                )

        time.sleep(0.001)


    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("-" * 70)

    print(
        f"[RESULT] TOTAL BYTES = {total_bytes}"
    )


finally:

    # --------------------------------------------------------
    # CLOSE UART
    # --------------------------------------------------------

    if ser is not None:

        try:
            ser.close()
            print("[UART] CLOSED")
        except:
            pass


    # --------------------------------------------------------
    # POWER OFF
    # --------------------------------------------------------

    print("[RELAY] CAMERA POWER OFF")

    GPIO.output(
        RELAY_PIN,
        GPIO.LOW
    )

    GPIO.cleanup()

    print("[GPIO] CLEANUP COMPLETE")

    print("=" * 70)
