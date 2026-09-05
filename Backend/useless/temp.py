import RPi.GPIO as GPIO
import time

RELAY_PIN = 6  # BCM GPIO 6 (Physical Pin 31)

GPIO.setmode(GPIO.BCM)
GPIO.setup(RELAY_PIN, GPIO.OUT)

# Set to True if your relay is active LOW
ACTIVE_LOW = False

try:
    for i in range(10):  # Repeat 10 times
        print(f"Cycle {i+1}: Relay ON")

        if ACTIVE_LOW:
            GPIO.output(RELAY_PIN, GPIO.LOW)
        else:
            GPIO.output(RELAY_PIN, GPIO.HIGH)

        time.sleep(10)  # ON for 1 second

        print(f"Cycle {i+1}: Relay OFF")

        if ACTIVE_LOW:
            GPIO.output(RELAY_PIN, GPIO.HIGH)
        else:
            GPIO.output(RELAY_PIN, GPIO.LOW)

        time.sleep(10)  # OFF for 1 second

finally:
    GPIO.cleanup()
