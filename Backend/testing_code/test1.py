import serial
import time
import RPi.GPIO as GPIO

RELAY_PIN = 6          # adjust to your actual relay GPIO
PORT = "/dev/ttyAMA10"
BAUD = 115200
LISTEN_DURATION = 10    # seconds to capture after power-on

GPIO.setmode(GPIO.BCM)
GPIO.setup(RELAY_PIN, GPIO.OUT, initial=GPIO.LOW)  # start with board OFF

try:
    ser = serial.Serial(PORT, BAUD, timeout=1)
    print(f"[OK] Opened {PORT} @ {BAUD}")

    print("[1] Ensuring board is OFF")
    GPIO.output(RELAY_PIN, GPIO.LOW)
    time.sleep(2)  # let it fully power down / discharge

    print("[2] Powering ON board and listening immediately")
    GPIO.output(RELAY_PIN, GPIO.HIGH)

    start = time.time()
    total_bytes = 0
    while time.time() - start < LISTEN_DURATION:
        data = ser.read(ser.in_waiting or 1)
        if data:
            total_bytes += len(data)
            print(data.decode(errors="replace"), end="", flush=True)

    print(f"\n\nTotal bytes received: {total_bytes}")

finally:
    ser.close()
    GPIO.output(RELAY_PIN, GPIO.LOW)
    GPIO.cleanup()
    print("Cleaned up: relay off, GPIO released, port closed")
