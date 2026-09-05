#!/usr/bin/env python3
import RPi.GPIO as GPIO
import time
import argparse
from datetime import datetime

# CLI args for flexibility
parser = argparse.ArgumentParser(description="Continuous ON with short glitch pulses (active-low support).")
parser.add_argument("--pin", type=int, default=22, help="BCM pin (default 22)")
parser.add_argument("--active-low", action="store_true", help="Use if LOW = ON (active-low).")
parser.add_argument("--glitch-duration", type=float, default=0.2, help="Glitch pulse duration in seconds (default 0.2s).")
parser.add_argument("--glitch-interval", type=float, default=5.0, help="Seconds between glitches (default 5s).")
parser.add_argument("--start-delay", type=float, default=1.0, help="Delay before script begins (seconds).")
parser.add_argument("--once", action="store_true", help="Run a single glitch then exit (for testing).")
args = parser.parse_args()

PIN = args.pin
ACTIVE_LOW = args.active_low
GLITCH_DURATION = args.glitch_duration
GLITCH_INTERVAL = args.glitch_interval
START_DELAY = args.start_delay

GPIO.setmode(GPIO.BCM)
GPIO.setup(PIN, GPIO.OUT)

def set_on():
    GPIO.output(PIN, GPIO.LOW if ACTIVE_LOW else GPIO.HIGH)

def set_off():
    GPIO.output(PIN, GPIO.HIGH if ACTIVE_LOW else GPIO.LOW)

print(f"[{datetime.now().isoformat()}] Script start. Pin={PIN} active_low={ACTIVE_LOW}")
print(f"Start delay {START_DELAY}s, glitch {GLITCH_DURATION}s every {GLITCH_INTERVAL}s")
time.sleep(START_DELAY)

# Ensure device is ON continuously initially
set_on()
print("Device set: ON (continuous)")

try:
    if args.once:
        # single glitch cycle for test
        time.sleep(GLITCH_INTERVAL)
        set_off()
        print(f"GLITCH OFF for {GLITCH_DURATION}s")
        time.sleep(GLITCH_DURATION)
        set_on()
        print("Back ON. Exiting (once).")
    else:
        # Continuous loop
        while True:
            time.sleep(GLITCH_INTERVAL)
            # Short glitch: turn OFF briefly
            set_off()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] GLITCH OFF for {GLITCH_DURATION}s")
            time.sleep(GLITCH_DURATION)
            set_on()
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Back ON")
except KeyboardInterrupt:
    print("\nInterrupted by user.")
finally:
    GPIO.cleanup()
    print("GPIO cleaned up. Exiting.")
