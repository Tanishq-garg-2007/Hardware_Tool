# Deployment & Configuration Guide for Raspberry Pi 5

This document outlines all hardware setup, system dependencies, configuration changes, and code considerations required when migrating and deploying this IoT Security project from Windows to **Raspberry Pi 5 (Raspberry Pi OS - Bookworm 64-bit)**.

---

## 1. Raspberry Pi 5 Hardware & Kernel Architecture Changes

Raspberry Pi 5 introduces the **RP1 southbridge I/O controller**, which completely redesigns how GPIO, SPI, and UART peripherals operate compared to earlier models (Pi 3 / Pi 4).

### Key Architectural Differences:
* **Direct `/dev/gpiomem` register access is deprecated**: Legacy `RPi.GPIO` library fails on Pi 5.
* **Drop-in Solution**: Use `rpi-lgpio` (which maps `import RPi.GPIO as GPIO` to the modern Linux `lgpio` driver) or `gpiozero`.
* **Config Path**: Configuration file is located at `/boot/firmware/config.txt` on Bookworm (instead of legacy `/boot/config.txt`).

---

## 2. Hardware Interfaces Setup (SPI, UART, GPIO)

### Step 1: Enable SPI & UART in `/boot/firmware/config.txt`
Edit the boot configuration:
```bash
sudo nano /boot/firmware/config.txt
```
Ensure the following lines are present and enabled:
```ini
dtparam=spi=on
enable_uart=1
```
Save and reboot (`sudo reboot`).

### Step 2: Configure UART Console (Disable Serial Login Shell)
If using hardware GPIO pins (GPIO 14 TX / GPIO 15 RX) for target board communication:
1. Run:
   ```bash
   sudo raspi-config
   ```
2. Navigate to: `Interface Options` -> `Serial Port`.
3. Would you like a login shell to be accessible over serial? -> **No**.
4. Would you like the serial port hardware to be enabled? -> **Yes**.
5. Finish and reboot.

### Step 3: Device Node Names on Raspberry Pi 5
| Interface | Raspberry Pi 5 Device Node | Windows Equivalent |
|---|---|---|
| **SPI Interface (for Flashrom)** | `/dev/spidev0.0` | N/A (Driver-specific) |
| **Primary Hardware UART** | `/dev/serial0` or `/dev/ttyAMA0` | `COMx` |
| **USB-to-UART Adapter** | `/dev/ttyUSB0` or `/dev/ttyACM0` | `COM3`, `COM4`, etc. |

---

## 3. System Packages & Tools Installation

Install required Linux binaries, reverse-engineering tools, and compilers:

```bash
sudo apt update && sudo apt install -y \
    build-essential \
    python3-dev \
    python3-venv \
    python3-pip \
    libgpiod-dev \
    libgpiod2 \
    flashrom \
    binwalk \
    squashfs-tools \
    binutils \
    p7zip-full \
    u-boot-tools \
    git \
    curl \
    nodejs \
    npm
```

### Add User to Hardware Groups (Avoid needing sudo for SPI/GPIO/Serial)
```bash
sudo usermod -aG gpio,spi,dialout $USER
```
*(Log out and log back in for group permissions to take effect)*

---

## 4. Backend Environment Setup (Python)

Raspberry Pi OS Bookworm enforces PEP 668 (externally managed environment). Always use a virtual environment.

```bash
cd ~/Hardware/Backend

# Create and activate virtual environment
python3 -m venv .venv --system-site-packages
source .venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install project requirements
pip install -r requirements.txt

# Install Raspberry Pi 5 GPIO compatibility layer
pip install rpi-lgpio
```

> **Note**: `rpi-lgpio` provides the exact `RPi.GPIO` module import for Pi 5, so scripts using `import RPi.GPIO as GPIO` (like `power_module.py` and `main.py`) will function without modifying the code syntax!

---

## 5. Shell Script Permissions

Ensure bash helper scripts have executable permissions:

```bash
cd ~/Hardware/Backend
chmod +x dump_flash.sh list_flash.sh firmwalker.sh
```

---

## 6. Ollama & LLM Models (For ChatBot & RAG)

If running local AI models on the Pi 5:

1. **Install Ollama on Linux**:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull Required Models**:
   ```bash
   ollama pull nomic-embed-text
   ollama pull qwen3.5:0.8b
   # Or alternatively: ollama pull llama3.2:3b
   ```

3. **Prevent Constant Model-Swapping on Pi 5 (CRITICAL)**:
   By default, Ollama only keeps 1 model loaded in RAM. Because RAG needs both the embedding model (`nomic-embed-text`) and the LLM (`qwen3.5:0.8b`), Ollama would otherwise swap them back and forth from the SD/NVMe drive on every query, causing 15-20s delays.
   
   To keep both active in RAM simultaneously:
   ```bash
   sudo mkdir -p /etc/systemd/system/ollama.service.d
   sudo tee /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
   [Service]
   Environment="OLLAMA_MAX_LOADED_MODELS=2"
   Environment="OLLAMA_NUM_PARALLEL=1"
   EOF
   sudo systemctl daemon-reload
   sudo systemctl restart ollama
   ```

4. **Configure Backend Environment (`Backend/.env`)**:
   ```ini
   SLM_MODEL=qwen3.5:0.8b
   EMBEDDING_MODEL=nomic-embed-text:latest
   SLM_CONTEXT_SIZE=4096
   SLM_NUM_PREDICT=1024
   SLM_TIMEOUT=180
   ```

---

## 7. Frontend Setup (Next.js)

```bash
cd ~/Hardware/front
npm install
npm run build
```

---

## 8. Production Deployment: Systemd Services

To make the Backend and Frontend start automatically on Raspberry Pi boot:

### 1. Backend Service (`/etc/systemd/system/iot-backend.service`)
```ini
[Unit]
Description=IoT Security Hardware Backend (FastAPI)
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/Hardware/Backend
# Pin Backend to CPU Core 0 for real-time UART streaming & GPIO timing
CPUAffinity=0
ExecStart=/home/pi/Hardware/Backend/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
```

### 2. Frontend Service (`/etc/systemd/system/iot-frontend.service`)
```ini
[Unit]
Description=IoT Security Hardware Frontend (Next.js)
After=network.target iot-backend.service

[Service]
User=pi
WorkingDirectory=/home/pi/Hardware/front
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=3
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
```

### Enable & Start Services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now iot-backend
sudo systemctl enable --now iot-frontend
```

---

## 9. Local AI & Ollama Setup on Raspberry Pi 5

For local LLM inference on Raspberry Pi 5:

### 1. Install Ollama on Linux:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Configure Ollama CPU Core Affinity:
To prevent the SLM from consuming Core 0 (which handles real-time UART streaming and GPIO glitching), pin Ollama to Cores 1, 2, and 3:
```bash
sudo systemctl edit ollama.service
```
Add the following lines:
```ini
[Service]
CPUAffinity=1,2,3
Environment="OLLAMA_NUM_PARALLEL=1"
```
Save and restart Ollama:
```bash
sudo systemctl restart ollama
```

### 3. Pull Recommended Lightweight Models:
```bash
# Vector embeddings for RAG & File Analysis
ollama pull nomic-embed-text

# Ultra-fast models for Complete Analysis, Chatbot & File Analysis
ollama pull qwen3.5:0.8b
ollama pull lfm2.5-thinking:1.2b
```

---

## 10. Hardware Wiring Guide

For full physical wiring instructions, TX/RX crossover diagrams, common ground rules, and SPI clip hookups, see:
* **[HARDWARE_WIRING_GUIDE.md](file:///c:/Users/tanis/OneDrive/Documents/IOT%20SECURITY/Hardware/backend/HARDWARE_WIRING_GUIDE.md)**
* Dynamic hardware configuration is handled automatically by:
  * **[hardware_config.py](file:///c:/Users/tanis/OneDrive/Documents/IOT%20SECURITY/Hardware/backend/hardware_config.py)**
* Diagnostic endpoint available at: `GET /hardware/info`

---

## 10. Checklist for Future Code Changes

Whenever adding or modifying features in this codebase:
- [ ] **Serial Ports**: Use Linux device paths (`/dev/ttyUSB0`, `/dev/serial0`, or dynamically list available ports using `serial.tools.list_ports`).
- [ ] **GPIO Access**: Use `rpi-lgpio` or `gpiozero`; do not rely on raw memory mapped registers (`/dev/mem` or `/dev/gpiomem`).
- [ ] **Binary Tools**: Invoke native Linux binaries (`flashrom`, `/usr/bin/strings`, `binwalk`, `mksquashfs`/`unsquashfs`).
- [ ] **File Paths**: Use `os.path.join` or `pathlib.Path` to prevent Windows backslash `\` path bugs on Linux.
- [ ] **Process Permissions**: Check SPI/UART/GPIO device permissions via udev rules or user groups.
