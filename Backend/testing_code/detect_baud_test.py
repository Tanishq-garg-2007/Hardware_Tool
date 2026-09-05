import serial
from time import sleep, time
from os import remove, path
import os

# ---------------- CONFIG ---------------- #
UART_PORT = "/dev/serial0"
BAUDRATES = [9600, 115200, 4800, 38400]
OUTPUT_FILE = "uart_logs/baud_output.txt"


# ---------------- CORE FUNCTION ---------------- #
def check_baud_output(baud_rate, delay, power_delay, power_thread):

    print(f"\n{'=' * 50}")
    print(f"[INFO] Testing baud: {baud_rate}")
    print(f"{'=' * 50}")

    # ---------------- POWER OFF ---------------- #
    print("[STEP] Power OFF")
    power_thread.set_state(0)
    sleep(power_delay)

    # ---------------- OPEN SERIAL BEFORE POWER ON ---------------- #
    try:
        ser = serial.Serial(
            port=UART_PORT,
            baudrate=baud_rate,
            timeout=0.1,
            write_timeout=1
        )

        # Clear any stale data
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        print(f"[INFO] Serial opened: {UART_PORT} @ {baud_rate}")

    except Exception as e:
        print(f"[ERROR] Serial open failed: {e}")
        return ""

    # ---------------- POWER ON ---------------- #
    print("[STEP] Power ON")
    power_thread.set_state(1)

    # ---------------- CAPTURE DATA ---------------- #
    start = time()

    output = f"\n\n===== USING {baud_rate} =====\n"

    try:

        while (time() - start) < delay:

            received_data = ser.read(ser.in_waiting or 1)

            if received_data:

                # Save raw data safely
                output += received_data.decode(
                    "utf-8",
                    errors="replace"
                )

                # Live display
                print(
                    received_data.decode(
                        "utf-8",
                        errors="replace"
                    ),
                    end="",
                    flush=True
                )

            sleep(0.01)

    except Exception as e:
        print(f"\n[ERROR] Read error: {e}")

    finally:
        ser.close()
        print(f"\n[INFO] Serial closed for {baud_rate}")

    # ---------------- SAVE OUTPUT ---------------- #
    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(output)

    except Exception as e:
        print(f"[ERROR] File write failed: {e}")

    return output


# ---------------- BAUD QUALITY ---------------- #
def calculate_baud_score(output):

    if not output:
        return 0

    # Remove our own header
    data = output.split("\n", 1)[-1]

    if not data:
        return 0

    printable = 0
    useful = 0
    garbage = 0

    for ch in data:

        # Normal printable ASCII
        if 32 <= ord(ch) <= 126:
            printable += 1

            # Characters commonly seen in boot logs
            if ch.isalnum() or ch in " :._-/=()[]{}@+,'\"":
                useful += 1

        # Common whitespace
        elif ch in "\r\n\t":
            useful += 1

        else:
            garbage += 1

    total = len(data)

    if total == 0:
        return 0

    printable_ratio = printable / total
    garbage_ratio = garbage / total

    # Score meaningful readable output
    score = (
        (printable_ratio * 70) +
        ((useful / total) * 30) -
        (garbage_ratio * 50)
    )

    return max(0, score)


# ---------------- MAIN FUNCTION ---------------- #
def run_baud_detection(
    sampling_time,
    power_cycle_delay,
    power_thread
):

    # Ensure folder exists
    log_dir = path.dirname(OUTPUT_FILE)

    if log_dir and not path.exists(log_dir):
        os.makedirs(log_dir)

    # Remove old file
    try:
        remove(OUTPUT_FILE)
    except FileNotFoundError:
        pass

    print("\n")
    print("=" * 60)
    print("        STARTING UART BAUD DETECTION")
    print("=" * 60)

    results = {}

    # ---------------- TEST ALL BAUDS ---------------- #
    for rate in BAUDRATES:

        output = check_baud_output(
            rate,
            int(sampling_time),
            int(power_cycle_delay),
            power_thread
        )

        score = calculate_baud_score(output)

        results[rate] = {
            "length": len(output),
            "score": score
        }

        print(f"\n[RESULT] Baud      : {rate}")
        print(f"[RESULT] Characters: {len(output)}")
        print(f"[RESULT] Score     : {score:.2f}")

    # ---------------- FIND BEST BAUD ---------------- #
    best_baud = max(
        results,
        key=lambda baud: results[baud]["score"]
    )

    print("\n")
    print("=" * 60)
    print(f"[FINAL RESULT] BEST BAUD: {best_baud}")
    print("=" * 60)

    # ---------------- SAVE FINAL RESULT ---------------- #
    try:

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:

            f.write("\n\n")
            f.write("=" * 50 + "\n")
            f.write("BAUD DETECTION RESULTS\n")
            f.write("=" * 50 + "\n")

            for baud, result in results.items():

                f.write(
                    f"Baud: {baud} | "
                    f"Characters: {result['length']} | "
                    f"Score: {result['score']:.2f}\n"
                )

            f.write(
                f"\nFINAL BEST BAUD: {best_baud}\n"
            )

    except Exception as e:
        print(f"[ERROR] Final result write failed: {e}")

    return best_baud