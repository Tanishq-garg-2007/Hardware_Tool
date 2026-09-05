import os
import sys
import glob

# =====================================================================
# RASPBERRY PI 5 HARDWARE ARCHITECTURE & PIN CONFIGURATION
# =====================================================================
# SoC: Broadcom BCM2712 Quad-Core ARM Cortex-A76 @ 2.4 GHz
# Southbridge I/O Controller: RP1 (connected over PCIe 2.0 x4)
# GPIO Driver: Linux lgpio / libgpiod via /dev/gpiochip4
# =====================================================================

def is_raspberry_pi_5() -> bool:
    """Detects whether this process is running natively on a Raspberry Pi 5."""
    try:
        model_path = "/sys/firmware/devicetree/base/model"
        if os.path.exists(model_path):
            with open(model_path, "r", encoding="utf-8", errors="ignore") as f:
                model_str = f.read()
                return "Raspberry Pi 5" in model_str
    except Exception:
        pass

    try:
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "BCM2712" in content or "Raspberry Pi 5" in content:
                    return True
    except Exception:
        pass

    return False

IS_PI_5 = is_raspberry_pi_5()

# ---------------------------------------------------------------------
# 1. 40-PIN HEADER BCM PIN ASSIGNMENTS
# ---------------------------------------------------------------------
# All pins operate at 3.3V CMOS logic (NOT 5V tolerant).
# ---------------------------------------------------------------------
RELAY_POWER_PIN = int(os.getenv("RELAY_POWER_PIN", "6"))         # BCM 6  (Physical Pin 31) - Active LOW / HIGH
OCTOCOUPLER_POWER_PIN = int(os.getenv("OCTOCOUPLER_POWER_PIN", "22")) # BCM 22 (Physical Pin 15) - Fast optical isolator switch
CHANNEL_PIN = int(os.getenv("CHANNEL_PIN", "26"))                 # BCM 26 (Physical Pin 37) - Glitch channel selector
VOLTAGE_GLITCH_PIN = int(os.getenv("VOLTAGE_GLITCH_PIN", "20"))   # BCM 20 (Physical Pin 38) - High-speed pulse trigger

# UART Hardware Pins on 40-Pin Header:
# TX (Transmit): BCM 14 (Physical Pin 8)  -> Connects to Target Device RX
# RX (Receive):  BCM 15 (Physical Pin 10) -> Connects to Target Device TX
# Ground (GND):  Physical Pin 6, 9, 14, 20, 25, 30, 34, or 39 -> MUST connect to Target Device GND!

# SPI Flashrom Hardware Pins (SPI Bus 0):
# MOSI: BCM 10 (Physical Pin 19) -> Flash SOIC8 Pin 5 (DI)
# MISO: BCM 9  (Physical Pin 21) -> Flash SOIC8 Pin 2 (DO)
# SCLK: BCM 11 (Physical Pin 23) -> Flash SOIC8 Pin 6 (CLK)
# CE0:  BCM 8  (Physical Pin 24) -> Flash SOIC8 Pin 1 (/CS)
# 3.3V: Physical Pin 1 or 17     -> Flash SOIC8 Pin 8 (VCC) - or external PSU
# GND:  Physical Pin 25          -> Flash SOIC8 Pin 4 (GND)

# ---------------------------------------------------------------------
# 2. DYNAMIC UART PORT RESOLUTION
# ---------------------------------------------------------------------
def get_uart_port() -> str:
    """
    Dynamically identifies the optimal UART serial port:
    1. Respects explicit UART_PORT environment variable if set.
    2. On Raspberry Pi 5, the 40-pin GPIO UART is PL011 at /dev/serial0 (or /dev/ttyAMA0).
       Legacy /dev/ttyS0 does NOT exist on the Pi 5.
    3. Checks for USB-to-UART adapters (/dev/ttyUSB0, /dev/ttyACM0).
    4. Falls back gracefully for local Windows/Linux dev environments.
    """
    custom_port = os.getenv("UART_PORT")
    if custom_port:
        return custom_port

    if os.name != "nt":
        # Candidate ports in priority order for Raspberry Pi 5 & Linux
        candidates = [
            "/dev/serial0",   # Official OS symlink to primary hardware UART
            "/dev/ttyAMA0",   # Direct PL011 UART on GPIO 14/15
            "/dev/ttyUSB0",   # CP2102, FTDI, CH340 USB dongle
            "/dev/ttyUSB1",
            "/dev/ttyACM0",   # CDC-ACM USB serial dongle
            "/dev/ttyS0",     # Legacy Pi 3/4 mini-UART (if present)
        ]
        for port in candidates:
            if os.path.exists(port):
                return port

        # Check glob for any other usb serial ports
        usb_ports = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
        if usb_ports:
            return usb_ports[0]

        # Default Linux fallback
        return "/dev/serial0" if IS_PI_5 else "/dev/ttyS0"
    else:
        # Windows development fallback
        return os.getenv("WINDOWS_SERIAL_PORT", "COM3")

# ---------------------------------------------------------------------
# 3. CORTEX-A76 CPU ARCHITECTURE & SLM THREAD ALLOCATION
# ---------------------------------------------------------------------
# Raspberry Pi 5 has 4 physical Cortex-A76 cores without SMT (hyperthreading).
# Small Language Model (SLM) inference is memory-bandwidth bound (~17 GB/s LPDDR4X).
# Spawning 4+ threads causes memory bus contention and thermal throttling.
# Optimal Allocation:
# - Core 0: Reserved for Linux OS, FastAPI/Uvicorn HTTP server, GPIO glitching, and UART streaming.
# - Cores 1, 2, 3: Dedicated to SLM neural inference (num_thread = 3).
# ---------------------------------------------------------------------
TOTAL_CORES = os.cpu_count() or 4

def get_slm_thread_count() -> int:
    """Calculates optimal thread allocation for local SLM/LLM inference."""
    env_threads = os.getenv("SLM_NUM_THREADS")
    if env_threads:
        try:
            return max(1, int(env_threads))
        except ValueError:
            pass

    # If quad-core (standard Pi 5), use 3 threads leaving Core 0 free for I/O
    if TOTAL_CORES <= 4:
        return max(1, TOTAL_CORES - 1)
    else:
        # On larger host machines, allocate up to 4 threads for SLM
        return min(4, max(1, TOTAL_CORES - 2))

SLM_NUM_THREADS = get_slm_thread_count()
SLM_CONTEXT_SIZE = int(os.getenv("SLM_CONTEXT_SIZE", "4096"))
SLM_TEMPERATURE = float(os.getenv("SLM_TEMPERATURE", "0.2"))
SLM_TIMEOUT = int(os.getenv("SLM_TIMEOUT", "180"))
SLM_NUM_PREDICT = int(os.getenv("SLM_NUM_PREDICT", "1024"))
SLM_MODEL = os.getenv("SLM_MODEL", "qwen3.5:0.8b")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text:latest")

# ---------------------------------------------------------------------
# 4. GPIO INITIALIZATION & COMPATIBILITY LAYER
# ---------------------------------------------------------------------
try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    import warnings
    warnings.warn("RPi.GPIO not found or not supported on this OS. Using MockGPIO for development.")
    class MockGPIO:
        BCM = "BCM"
        OUT = "OUT"
        IN = "IN"
        HIGH = 1
        LOW = 0
        def setmode(self, mode): pass
        def setup(self, channel, direction, *args, **kwargs): pass
        def output(self, channel, state): pass
        def input(self, channel): return 0
        def cleanup(self, *args, **kwargs): pass
        def setwarnings(self, flag): pass
        def getmode(self): return "BCM"
    GPIO = MockGPIO()

    # Register in sys.modules so child scripts importing RPi.GPIO get MockGPIO
    class MockRPi:
        GPIO = GPIO
    sys.modules['RPi'] = MockRPi()
    sys.modules['RPi.GPIO'] = GPIO

def get_gpio():
    """Returns the initialized GPIO provider (native rpi-lgpio or MockGPIO)."""
    return GPIO

# ---------------------------------------------------------------------
# 5. HARDWARE SYSTEM DIAGNOSTICS PAYLOAD
# ---------------------------------------------------------------------
def get_hardware_diagnostics() -> dict:
    """Generates a complete hardware diagnostic snapshot for Pi 5."""
    active_port = get_uart_port()
    port_exists = os.path.exists(active_port) if os.name != "nt" else False

    return {
        "platform": sys.platform,
        "is_pi_5": IS_PI_5,
        "cpu_cores": TOTAL_CORES,
        "slm_thread_allocation": SLM_NUM_THREADS,
        "slm_context_size": SLM_CONTEXT_SIZE,
        "active_uart_port": active_port,
        "uart_port_accessible": port_exists,
        "pins": {
            "relay_power_bcm": RELAY_POWER_PIN,
            "relay_power_physical": 31,
            "octocoupler_power_bcm": OCTOCOUPLER_POWER_PIN,
            "octocoupler_power_physical": 15,
            "glitch_channel_bcm": CHANNEL_PIN,
            "glitch_channel_physical": 37,
            "voltage_glitch_bcm": VOLTAGE_GLITCH_PIN,
            "voltage_glitch_physical": 38,
            "uart_tx_bcm": 14,
            "uart_tx_physical": 8,
            "uart_rx_bcm": 15,
            "uart_rx_physical": 10,
            "spi0_mosi_physical": 19,
            "spi0_miso_physical": 21,
            "spi0_sclk_physical": 23,
            "spi0_ce0_physical": 24,
            "logic_voltage": "3.3V CMOS"
        }
    }
