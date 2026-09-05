# Complete Hardware-Level Wiring & Connection Guide
## IoT Security Auditing Platform on Raspberry Pi 5

This guide provides the complete hardware-level wiring specifications, pin assignments, electrical principles, serial communication concepts (TX/RX crossover, common ground), and end-to-end testing runbooks for running this security suite on the **Raspberry Pi 5**.

---

## 1. Raspberry Pi 5 Architecture Overview

The **Raspberry Pi 5** introduces a fundamentally redesigned hardware layout:

```
+-----------------------------------------------------------------------+
|                       Raspberry Pi 5 Architecture                      |
|                                                                       |
|  +-----------------------------+       PCIe 2.0 x4     +------------+ |
|  | Broadcom BCM2712 SoC        | <===================> | RP1 South- | |
|  | - Quad-Core Cortex-A76      |                       | bridge I/O | |
|  |   @ 2.4 GHz                 |                       +-----+------+ |
|  | - 512KB L2 per core         |                             |        |
|  | - 2MB Shared L3 Cache       |                             |        |
|  | - 4GB / 8GB LPDDR4X SDRAM   |                             v        |
|  +-----------------------------+                   [40-Pin GPIO Header|
|                 |                                   UART, SPI, I2C,   |
|                 v                                   PWM, USB, Eth]    |
|   CPU Core & Thread Assignment:                                       |
|   * Core 0: Linux OS, FastAPI Backend, UART streaming, GPIO timing    |
|   * Cores 1, 2, 3: Small Language Model (SLM / Ollama neural inference)|
+-----------------------------------------------------------------------+
```

### Critical Electrical Principles:
> [!CAUTION]
> **3.3V CMOS Logic Level Warning:**
> All 40-pin GPIO lines on the Raspberry Pi 5 operate strictly at **3.3V logic**.
> **THEY ARE NOT 5V TOLERANT.**
> Directly connecting a 5V UART or 5V GPIO signal from an Arduino or legacy 5V embedded board directly to the Pi 5 will permanently damage the RP1 I/O controller! Use an optocoupler, logic-level shifter, or voltage divider.

---

## 2. Raspberry Pi 5 40-Pin Header Mapping Table

The table below lists the physical pins, Broadcom (BCM) numbers, and their configured function in this project:

| Physical Pin # | Pin Name / BCM | Project Hardware Function | Wire Color Recommendation |
| :---: | :---: | :---: | :---: |
| **Pin 1** | **3.3V Power** | Target Power (Low current < 50mA) / Pullup | Red |
| **Pin 2** | **5.0V Power** | Power for Relay Module VCC | Orange |
| **Pin 4** | **5.0V Power** | Auxiliary 5V Power | Orange |
| **Pin 6** | **GND (Ground)** | Common Ground to Target & Modules | Black |
| **Pin 8** | **GPIO 14 (UART0 TX)** | **UART Transmit $\rightarrow$ Target RX** | Blue |
| **Pin 10** | **GPIO 15 (UART0 RX)** | **UART Receive $\leftarrow$ Target TX** | Green |
| **Pin 14** | **GND (Ground)** | UART Reference Ground | Black |
| **Pin 15** | **GPIO 22** | **Octocoupler Power Switch Control** | Yellow |
| **Pin 17** | **3.3V Power** | SPI Flash 3.3V Power Rail | Red |
| **Pin 19** | **GPIO 10 (SPI0 MOSI)**| **SPI Data In to Flash (SOIC8 Pin 5 - DI)** | Purple |
| **Pin 20** | **GND (Ground)** | Ground | Black |
| **Pin 21** | **GPIO 9 (SPI0 MISO)** | **SPI Data Out from Flash (SOIC8 Pin 2 - DO)** | White |
| **Pin 23** | **GPIO 11 (SPI0 SCLK)**| **SPI Clock (SOIC8 Pin 6 - CLK)** | Gray |
| **Pin 24** | **GPIO 8 (SPI0 CE0)**  | **SPI Chip Enable (SOIC8 Pin 1 - /CS)** | Brown |
| **Pin 25** | **GND (Ground)** | SPI Common Ground | Black |
| **Pin 31** | **GPIO 6** | **Electromechanical Relay Control** | Yellow |
| **Pin 37** | **GPIO 26** | **Voltage Glitch Channel Selector** | White / Striped |
| **Pin 38** | **GPIO 20** | **Voltage Glitch Pulse Trigger** | Brown / Striped |
| **Pin 39** | **GND (Ground)** | Common Ground | Black |

---

## 3. Fundamental Serial & Hardware Concepts

### Concept A: The TX / RX Crossover Rule
Serial UART is an asynchronous point-to-point protocol consisting of separate transmit (`TX`) and receive (`RX`) lines.

```
+-------------------+                       +-------------------+
|  Raspberry Pi 5   |                       |   Target Device   |
|                   |                       |   (Router/Camera) |
|   TX (Pin 8)   ---+---------------------> |---> RX Pin        |
|                   |   (Transmit Data)     |                   |
|   RX (Pin 10)  <--+-----------------------+---- TX Pin        |
|                   |    (Receive Data)     |                   |
|   GND (Pin 6)  <--========================+---> GND           |
|                   |    (Reference Zero)   |                   |
+-------------------+                       +-------------------+
```

* **Mouth-to-Ear Analogy**:
  * `TX` is the "mouth" (speaker).
  * `RX` is the "ear" (listener).
  * If you wire `TX` to `TX` (mouth to mouth) and `RX` to `RX` (ear to ear), **no device will ever receive any data**!
  * **Always crossover:** Pi TX connects to Target RX, and Pi RX connects to Target TX.

---

### Concept B: The Common Ground (GND) Rule
> [!IMPORTANT]
> **Voltage is Relative, Not Absolute!**
> A digital "HIGH" (3.3V) is defined as 3.3 volts *above ground*. If the Raspberry Pi 5 and the target device are powered from separate power supplies and do not share a common ground wire:
> 1. Their reference points will float relative to each other.
> 2. The UART receiver will see erratic, random voltage swings.
> 3. Symptoms: Baud rate detection will fail, console output will look like `?x`, or baud rate detector will report `None`.
> **Solution:** Always run a physical jumper wire from a Raspberry Pi GND pin (e.g., Pin 6 or 14) to the Target Device GND pin.

---

## 4. Component-by-Component Wiring Diagrams

### Mode 1: Electromechanical Relay Module Setup
Used for automatic power cycling during baud rate detection and bootlog capture.

```
       Raspberry Pi 5                           Relay Module
     +-----------------+                     +-----------------+
     | Pin 2  (5V)     |-------------------->| VCC             |
     | Pin 6  (GND)    |-------------------->| GND             |
     | Pin 31 (GPIO 6) |-------------------->| IN1 (Trigger)   |
     +-----------------+                     +-----------------+
                                               |             |
                                              COM            NO (Normally Open)
                                               |             |
                                    [External PSU +]     [Target VCC +]
```

1. Connect Pi Pin 2 (5V) $\rightarrow$ Relay VCC.
2. Connect Pi Pin 6 (GND) $\rightarrow$ Relay GND.
3. Connect Pi Pin 31 (GPIO 6) $\rightarrow$ Relay IN / Trigger.
4. Cut the positive (+) wire of the target device's power supply:
   * Connect one side to **COM** (Common).
   * Connect the target power input side to **NO** (Normally Open).
   * Result: When GPIO 6 activates, the relay closes and powers on the target device.

---

### Mode 2: Octocoupler (Optical Isolator) Setup
Provides sub-microsecond power switching and electrical isolation, preventing voltage spikes from reaching the Pi 5.

```
       Raspberry Pi 5                       PC817 Optocoupler Module
     +------------------+                     +------------------+
     | Pin 1  (3.3V)    |-------------------->| VCC (Input Side) |
     | Pin 15 (GPIO 22) |-------------------->| IN  (Input Side) |
     | Pin 14 (GND)     |-------------------->| GND (Input Side) |
     +------------------+                     +------------------+
                                                |              |
                                              OUT +          OUT -
                                                |              |
                                          [Target Power Switch Rail]
```

1. Connect Pi Pin 1 (3.3V) $\rightarrow$ Module VCC (Input side).
2. Connect Pi Pin 15 (GPIO 22) $\rightarrow$ Module IN (Trigger).
3. Connect Pi Pin 14 (GND) $\rightarrow$ Module GND (Input ground).
4. Connect the output collector/emitter across the target device's power control rail.

---

### Mode 3: SPI Flash Extractor (`flashrom` with SOIC8 Clip)
Used for dumping raw SPI NOR flash memory (e.g. Winbond W25Q128, Macronix MX25L).

```
   Raspberry Pi 5 SPI0 Pin                  SOIC8 Flash Chip Pin
 +-------------------------------+        +-------------------------------+
 | Pin 24 (GPIO 8  / SPI0 CE0)   | -----> | Pin 1 (/CS  - Chip Select)    |
 | Pin 21 (GPIO 9  / SPI0 MISO)  | <----- | Pin 2 (DO   - Data Output)    |
 | Pin 1  (3.3V Power - Optional)| -----> | Pin 3 (/WP  - Write Protect)  |
 | Pin 25 (GND)                  | -----> | Pin 4 (GND  - Ground)         |
 | Pin 19 (GPIO 10 / SPI0 MOSI)  | -----> | Pin 5 (DI   - Data Input)     |
 | Pin 23 (GPIO 11 / SPI0 SCLK)  | -----> | Pin 6 (CLK  - Clock)          |
 | Pin 1  (3.3V Power - Optional)| -----> | Pin 7 (/HOLD- Hold Input)     |
 | Pin 1 or 17 (3.3V Power)      | -----> | Pin 8 (VCC  - 3.3V Power)     |
 +-------------------------------+        +-------------------------------+
```

> [!TIP]
> **In-Circuit vs Desoldered Extraction:**
> If extracting in-circuit (clip attached while chip is on target PCB), the target board's CPU and peripherals may also draw power from Pin 1/17, causing voltage sag.
> In the Web UI (`/spi`), select **External PSU Power** and power the target board via its normal DC power jack while connecting ONLY MOSI, MISO, SCLK, CE0, and GND to the Pi 5.

---

## 5. End-to-End Hardware Test Runbook

Follow these 5 steps to verify your hardware setup with any target device:

### Step 1: Pre-Flight Architecture & Pin Check
Verify that the backend has initialized the Pi 5 hardware mappings:
```bash
curl -s http://localhost:8000/hardware/info | jq .
```
Expected output:
```json
{
  "platform": "linux",
  "is_pi_5": true,
  "cpu_cores": 4,
  "slm_thread_allocation": 3,
  "active_uart_port": "/dev/serial0",
  "uart_port_accessible": true,
  "pins": {
    "relay_power_bcm": 6,
    "octocoupler_power_bcm": 22,
    "logic_voltage": "3.3V CMOS"
  }
}
```

---

### Step 2: Test Power Relay / Optocoupler Toggle
Test the physical switching without connecting the target yet:
* **Relay Mode**:
  ```bash
  # Turn Power OFF
  curl http://localhost:8000/switch_power/0
  # Turn Power ON (Listen for relay audible click)
  curl http://localhost:8000/switch_power/1
  ```
* **Octocoupler Mode**:
  ```bash
  # Turn Power OFF
  curl http://localhost:8000/new_switch_power/0
  # Turn Power ON
  curl http://localhost:8000/new_switch_power/1
  ```

---

### Step 3: Test UART Loopback (Verify Port & Pins)
Before attaching the target, perform a loopback test:
1. Connect a physical jumper wire between **Pin 8 (TX)** and **Pin 10 (RX)** on the Pi 5.
2. In a Python terminal, run:
   ```python
   import serial
   s = serial.Serial("/dev/serial0", 115200, timeout=1)
   s.write(b"PI5_LOOPBACK_TEST\n")
   print("Received:", s.readline())
   ```
3. If it prints `Received: b'PI5_LOOPBACK_TEST\n'`, your hardware UART controller, driver, and pins are functioning 100%. Remove the jumper.

---

### Step 4: Detect Target Baud Rate
1. Connect Target TX $\rightarrow$ Pi Pin 10 (RX).
2. Connect Target RX $\rightarrow$ Pi Pin 8 (TX).
3. Connect Target GND $\rightarrow$ Pi Pin 6 (GND).
4. Connect Target Power through the Relay or Optocoupler.
5. In the Web UI (`/uart?mode=relay`), click **Detect Baudrate**.
   * The tool will power cycle the device, capture boot characters across all standard baud rates, and score the printable ASCII density.
   * If detected (e.g. `115200`), it displays the recommended baud rate.
   * If wiring or power is disconnected, it displays: *"No valid UART console traffic detected."*

---

### Step 5: Capture Bootlog & Run Vulnerability Assessment
1. In the Web UI, click **Capture Bootlog**.
2. Wait for the boot sequence to stream into the terminal.
3. Click **Analyze Bootlog** or go to **File Analysis** to inspect:
   * U-Boot console access
   * Root shell prompts (`# `, `root@`)
   * Hardcoded credentials & private keys
   * Automated CVE & EPSS vulnerability scores.
