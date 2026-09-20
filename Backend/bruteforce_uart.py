import os
from pathlib import Path
import serial
import sys
from time import sleep, time

from hardware_config import get_uart_port

output_file = "uart_logs/uart_bruteforce_log"

SCRIPT_DIR = Path(__file__).resolve().parent
combolist = str(SCRIPT_DIR / "bruteforce_combo.txt") if (SCRIPT_DIR / "bruteforce_combo.txt").exists() else str(SCRIPT_DIR / "bruteforce_combo")

def check_login(baud_rate, fail_key, cred):
    if not cred or ":" not in cred:
        return False

    port = get_uart_port()
    try:
        ser = serial.Serial(port, baud_rate, timeout=1.5)
    except Exception as e:
        print(f"[ERROR] Could not open {port}: {e}")
        return False

    try:
        parts = cred.split(":", 1)
        username = parts[0].strip()
        password = parts[1].strip() if len(parts) > 1 else ""

        ser.write(username.encode("ascii", errors="ignore") + b"\r\n")
        sleep(0.3)
        ser.write(password.encode("ascii", errors="ignore") + b"\r\n")
        sleep(0.5)

        received_bytes = b""
        start_t = time()
        while time() - start_t < 1.5:
            if ser.in_waiting:
                received_bytes += ser.read(ser.in_waiting)
            sleep(0.05)

        temp = received_bytes.decode("ascii", errors="ignore")
        if fail_key.lower() in temp.lower():
            return False
        return bool(received_bytes)
    except Exception as e:
        print(f"[ERROR] Login check exception: {e}")
        return False
    finally:
        try:
            ser.close()
        except Exception:
            pass

def main():
    if len(sys.argv) < 2:
        print("Usage: bruteforce_uart.py <baud_rate>")
        return

    baud_rate = int(sys.argv[1])
    fail_key = "Invalid Password"

    if not os.path.exists(combolist):
        print(f"[ERROR] Combo file '{combolist}' not found.")
        return

    with open(combolist, "r", encoding="utf-8", errors="ignore") as f:
        for cred in f:
            cred_str = cred.strip()
            if not cred_str:
                continue
            print("Checking:", cred_str)
            if check_login(baud_rate, fail_key, cred_str):
                print("[SUCCESS] Working credentials found:", cred_str)
                return cred_str
            else:
                print(cred_str, "Not working")

#main()
