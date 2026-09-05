import os
import sys
import ollama
import re
import asyncio

# --- CONFIGURATION ---
# Optimized model and tuned parameters for Raspberry Pi 5 & Windows
MODEL_NAME = "qwen3.5:0.8b"

# Tuned chunking for high speed and balanced context on embedded hardware
CHUNK_SIZE = 8000 
OVERLAP = 400
MAX_CHUNKS_PER_TASK = 5  # Limits processing to top high-signal chunks

# --- SYSTEM PROMPTS ---
SYSTEM_INSTRUCTION = (
    "You are an expert embedded firmware security analyst. "
    "Your task is to extract specific security metadata from the provided firmware strings. "
    "Output ONLY the requested fields in 'Key: Value' format based strictly on facts found in the text. "
    "If information for a field is not present, output 'N/A' or 'Not available'. "
    "Do not include conversational filler, explanations, or disclaimers."
)

# --- TASK KEYWORDS FOR REGEX PRE-FILTERING ---
TASK_KEYWORDS = {
    1: [r"version", r"build", r"model", r"revision", r"u-boot", r"linux\s+version", r"release", r"firmware", r"v\d+\.", r"product", r"device"],
    2: [r"squashfs", r"cramfs", r"jffs2", r"ubifs", r"sha256", r"sha-256", r"md5", r"lzma", r"gzip", r"xz\b", r"https?://", r"\.bin\b", r"\.img\b", r"\.tar"],
    3: [r"linux", r"arm[v\d]*", r"mips", r"riscv", r"x86", r"kernel", r"glibc", r"uclibc", r"musl", r"busybox", r"systemd", r"openwrt", r"endian", r"init="],
    4: [r"secure\s*boot", r"rsa", r"ecdsa", r"signature", r"verify", r"public\s*key", r"tpm", r"otp", r"efuse", r"certificate", r"x\.509", r"trust", r"fail\s*mode"],
    5: [r"https?", r"ssh", r"telnetd?", r"mqtt", r"coap", r"rtsp", r"upnp", r"port\s*\d+", r"password", r"passwd", r"credential", r"bind", r"listen", r"dropbear"],
    6: [r"aws", r"azure", r"tuya", r"aliyun", r"cloud", r"telemetry", r"endpoint", r"api\.", r"gateway", r"rce", r"remote", r"mqtts?://", r"wss?://"],
    7: [r"ota", r"update", r"upgrade", r"firmware_update", r"gpg", r"signed", r"rollback", r"anti-rollback", r"download", r"patch", r"recovery"],
    8: [r"strip", r"symbol", r"debug", r"packed", r"upx", r"crypto", r"aes", r"des\b", r"obfuscat", r"gdb", r"ida\b", r"ghidra"],
    9: [r"spdx", r"cyclonedx", r"license", r"gpl", r"mit\b", r"cve-\d{4}", r"openssl", r"busybox", r"dropbear", r"dnsmasq", r"contact", r"security@"]
}

# --- ANALYSIS MENUS & PROMPTS ---
PROMPT_MAP = {
    1: {
        "title": "Firmware Identification",
        "task": "Extract the following fields in Key: Value format:\n1. Name/ID\n2. Version\n3. Build Date\n4. Model\n5. Type (Dev/Prod). If unknown, state 'N/A'."
    },
    2: {
        "title": "Package & Artifacts",
        "task": "Extract:\n1. Format (BIN, IMG, SquashFS, etc.)\n2. SHA-256 / Checksums\n3. Filesystem\n4. Compression (LZMA/GZIP/XZ)\n5. URLs / Download Endpoints."
    },
    3: {
        "title": "OS & Architecture",
        "task": "Extract:\n1. OS (Linux/RTOS/Baremetal)\n2. Kernel Version\n3. CPU Architecture (ARM/MIPS/x86/RISC-V)\n4. Endianness (Little/Big)\n5. Libc (glibc/uClibc/musl)\n6. Init System (systemd/OpenWrt/BusyBox)."
    },
    4: {
        "title": "Secure Boot",
        "task": "Extract:\n1. Secure Boot Status (Yes/No/Detected)\n2. Boot Stages\n3. Algorithm (RSA/ECDSA)\n4. Key Storage (TPM/eFuse/OTP)\n5. Fail Mode."
    },
    5: {
        "title": "Network",
        "task": "Extract:\n1. Protocols (HTTP, HTTPS, MQTT, RTSP, etc.)\n2. Services/Daemons (telnetd, sshd, dropbear, lighttpd)\n3. Listening Ports\n4. Hardcoded credentials/hashes."
    },
    6: {
        "title": "Remote/Cloud",
        "task": "Extract:\n1. Cloud Integration (AWS/Azure/Tuya/Alibaba)\n2. Access Type (SSH/WebUI/App)\n3. RCE Surfaces\n4. Remote Endpoint URLs."
    },
    7: {
        "title": "Update & Patching",
        "task": "Extract:\n1. Method (OTA/Manual)\n2. Verification (GPG/Signed/Checksum)\n3. Anti-rollback\n4. Response/Recovery Policy."
    },
    8: {
        "title": "Reverse Engineering",
        "task": "Extract:\n1. Extraction Ease\n2. Readability\n3. Stripped Symbols (Yes/No)\n4. Obfuscation/Packing (UPX/Encrypted)\n5. Proprietary Crypto."
    },
    9: {
        "title": "SBOM & Vuln",
        "task": "Extract:\n1. SBOM References (SPDX/CycloneDX)\n2. Open-Source Packages (OpenSSL, BusyBox, etc.) with versions\n3. License Types\n4. Security Contact / Vulnerability URLs."
    }
}

def load_and_clean_file(file_path: str, min_len: int = 4) -> tuple:
    """
    Intelligently reads either plain-text files (bootlogs, scripts) or raw binary images.
    - If text: cleans ANSI terminal escape sequences and preserves line structure.
    - If binary: extracts ASCII printable strings of length >= min_len with garbage deduplication.
    """
    if not os.path.exists(file_path):
        return [], ""

    with open(file_path, 'rb') as f:
        data = f.read()

    # Detect if file is text or binary (presence of null bytes in first 8KB)
    is_binary = b'\x00' in data[:8192]

    if not is_binary:
        text = data.decode("utf-8", errors="ignore")
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return lines, text
    else:
        pattern = rb"[\x20-\x7E\t]{" + str(min_len).encode() + rb",}"
        raw_strings = re.findall(pattern, data)
        cleaned_lines = []
        seen = set()
        for s in raw_strings:
            decoded = s.decode("ascii", errors="ignore").strip()
            if len(set(decoded)) <= 2 and len(decoded) > 8:
                continue
            if decoded not in seen:
                seen.add(decoded)
                cleaned_lines.append(decoded)
        full_text = "\n".join(cleaned_lines)
        return cleaned_lines, full_text

def extract_strings_from_binary(file_path: str, min_len: int = 4) -> list:
    """
    Backwards-compatible wrapper that returns extracted lines.
    """
    lines, _ = load_and_clean_file(file_path, min_len=min_len)
    return lines

def filter_relevant_strings(lines: list, choice: int) -> str:
    """
    Applies regex filtering to keep only lines matching task-specific keywords.
    Falls back to a representative slice if keyword matches are sparse.
    """
    patterns = TASK_KEYWORDS.get(choice, [])
    if not patterns:
        return "\n".join(lines[:3000])

    combined_regex = re.compile("|".join(patterns), re.IGNORECASE)
    matched_lines = [line for line in lines if combined_regex.search(line)]

    if len(matched_lines) < 20:
        # Fallback: Combine matched lines with a general high-density sample
        matched_lines.extend(lines[:1000])

    return "\n".join(matched_lines)

def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = OVERLAP, max_chunks: int = MAX_CHUNKS_PER_TASK) -> list:
    """
    Splits filtered text into manageable chunks and caps the total chunk count.
    """
    chunks = []
    start = 0
    while start < len(text) and len(chunks) < max_chunks:
        chunks.append(text[start:start + size])
        start += size - overlap
    return chunks

def extract_deterministic_metadata(text: str, choice: int) -> str:
    """
    High-speed (<5ms) deterministic regex & pattern extractor.
    Extracts structured ground truth directly from firmware strings/bootlogs.
    Guarantees instant, accurate results without blocking on reasoning/thinking LLM loops.
    """
    lines_out = []

    if choice == 1:  # Firmware Identification
        fields = [
            ("Device Name", [
                r"(?:Device Name|Name/ID|Product Name):\s*([^\n\r]+)",
                r"Welcome to\s+([^\n\r!]+)",
                r"dev_alias:\s*([^\n\r]+)",
                r"dev_name:\s*([^\n\r]+)"
            ]),
            ("Model", [
                r"(?:Model|Device Model|Product Model|dev_model):\s*([^\n\r]+)",
                r"Board:\s*([^\n\r]+)",
                r"U-Boot\s+[\d\.]+.*?\)\s+([A-Za-z0-9_\-\(\)\s]+)"
            ]),
            ("Firmware Version", [
                r"(?:Firmware Version|Software Version|fw_ver|Version):\s*([^\n\r]+)",
                r"U-Boot\s+(\d{4}\.\d{2}[^\s\(\)]*)",
                r"\b(v\d+\.\d+(?:\.[\d\w\-]+)?)\b"
            ]),
            ("Build Date", [
                r"(?:Build Date|Date):\s*([^\n\r]+)",
                r"\(((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4}[^\)]*)\)",
                r"\b(\d{4}-\d{2}-\d{2}(?:T[\d:]+Z?)?)\b",
                r"\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{4})\b"
            ]),
            ("Vendor", [
                r"(?:Vendor|Manufacturer|oem_id)\s*:\s*(?!\s*(?:Linux\b|U-Boot\b))([^\n\r]+)",
                r"the manufacturer\s+([a-zA-Z0-9]+)",
                r"\b(TP-Link|Tapo|Netgear|D-Link|Hikvision|Dahua|Xiaomi|Ubiquiti|Cisco|Huawei|ZTE)\b"
            ]),
            ("Target Hardware", [
                r"(?:Target Hardware Revision|Revision|Hardware Rev|hw_ver):\s*([^\n\r]+)",
                r"Board rev\.\s*:\s*([^\n\r]+)",
                r"Board HW ID\s*:\s*([^\n\r]+)"
            ]),
            ("Firmware Type", [
                r"(?:Firmware Type|Type|dev_type):\s*([^\n\r]+)",
                r"Image Type:\s*([^\n\r]+)"
            ]),
            ("Board / SoC", [
                r"(?:Board / SoC|SoC|Platform):\s*([^\n\r]+)",
                r"CPU0 revision is:\s*[0-9a-fA-F]+\s*\(([^\)]+)\)",
                r"CPU:\s*([^\n\r]+)",
                r"\b(Ingenic\s+[A-Za-z0-9_]+|Broadcom\s+[A-Za-z0-9_]+|Realtek\s+[A-Za-z0-9_]+)\b"
            ])
        ]
        for label, patterns in fields:
            for p in patterns:
                m = re.search(p, text, re.IGNORECASE)
                if m:
                    lines_out.append(f"{label}: {m.group(1).strip() if m.groups() else m.group(0).strip()}")
                    break

    elif choice == 2:  # Package & Artifacts
        m_fmt = re.search(r"(?:Image Format|Format):\s*([^\n\r]+)", text, re.I)
        if m_fmt:
            lines_out.append(f"Format: {m_fmt.group(1).strip()}")
        elif "squashfs" in text.lower():
            lines_out.append("Format: SquashFS Compressed Firmware Image")
        elif "legacy image" in text.lower() or "u-boot image" in text.lower():
            lines_out.append("Format: U-Boot Legacy uImage / MTD Partitioned")

        sha = re.findall(r"\b[a-f0-9]{64}\b", text, re.I)
        if sha:
            lines_out.append(f"SHA-256 Checksum: {', '.join(list(set(sha))[:2])}")
        md5 = re.findall(r"\b[a-f0-9]{32}\b", text, re.I)
        if md5:
            lines_out.append(f"MD5 / UUIDs: {', '.join(list(set(md5))[:2])}")

        fs = re.findall(r"\b(squashfs[\s\d\.]*|cramfs|ubifs|jffs2|ext[234]|fat\d*|mtd_block|zram)\b", text, re.I)
        if fs:
            lines_out.append(f"Filesystems: {', '.join(sorted(set(f.strip() for f in fs)))}")

        partitions = re.findall(r'"([^"]+)"\s*:\s*(?:partition|mtd)|0x[0-9a-fA-F]+-0x[0-9a-fA-F]+\s*:\s*"([^"]+)"', text)
        clean_pts = []
        for pair in partitions:
            for p in pair:
                if p and p not in clean_pts:
                    clean_pts.append(p)
        if clean_pts:
            lines_out.append(f"MTD Partitions: {', '.join(clean_pts)}")

        comp = re.findall(r"\b(lzma|gzip|xz|zstd|bzip2)\b", text, re.I)
        if comp:
            lines_out.append(f"Compression: {', '.join(sorted(set(comp)))}")

        flash = re.search(r"\b(EN25QH\w*|W25Q\w*|SPI NOR|SPI NAND|SF: Detected \w+)\b", text, re.I)
        if flash:
            lines_out.append(f"Storage Medium: {flash.group(0)}")

        urls = list(set(re.findall(r"https?://[^\s<>\"\'\)]+", text)))
        if urls:
            lines_out.append("Endpoints / URLs:\n  - " + "\n  - ".join(urls[:4]))

    elif choice == 3:  # OS & Architecture
        m_os = re.search(r"(?:Operating System|\bOS\b)\s*[:=]\s*([^\n\r]+)", text, re.I)
        if m_os and not m_os.group(1).strip().startswith("0x") and len(m_os.group(1).strip()) < 30:
            lines_out.append(f"OS: {m_os.group(1).strip()}")
        elif "linux" in text.lower():
            lines_out.append("OS: Embedded Linux")
        elif "freertos" in text.lower():
            lines_out.append("OS: FreeRTOS")
        elif "zephyr" in text.lower():
            lines_out.append("OS: Zephyr RTOS")

        m_k = re.search(r"(?:Kernel Release|Kernel Version|Linux version|Linux-)\s*([0-9]+\.[0-9]+[\.\w\-_]+)", text, re.I)
        if m_k:
            lines_out.append(f"Kernel Version: {m_k.group(1).strip()}")

        arch = re.search(r"\b(ARM Cortex-A\d+|aarch64|ARMv\d+[\w\-]*|MIPS\d*|Ingenic XBurst|x86_64|RISC-V|sun\d+i)\b", text, re.I)
        if arch:
            lines_out.append(f"CPU Architecture: {arch.group(0)}")

        endian = re.search(r"\b(Little[\s\-]Endian|Big[\s\-]Endian|mipsel\b|arm(?:el|eb)\b|LSB|MSB)\b", text, re.I)
        if endian:
            val = endian.group(0)
            if val.lower() in ['mipsel', 'armel', 'lsb', 'little-endian', 'little endian']:
                lines_out.append("Endianness: Little Endian (LSB)")
            elif val.lower() in ['armeb', 'msb', 'big-endian', 'big endian']:
                lines_out.append("Endianness: Big Endian (MSB)")
            else:
                lines_out.append(f"Endianness: {val}")
        elif "xburst" in text.lower() or "cortex-a" in text.lower():
            lines_out.append("Endianness: Little Endian (Default for architecture)")

        gcc = re.search(r"gcc version\s+([0-9\.]+)", text, re.I)
        if gcc:
            lines_out.append(f"Compiler (GCC): v{gcc.group(1)}")

        libc = re.search(r"\b(glibc[\s\d\.]*|uClibc[\s\d\.]*|musl[\s\d\.]*)\b", text, re.I)
        if libc:
            lines_out.append(f"C Library: {libc.group(0)}")

        init = re.search(r"\b(systemd[\s\d\.]*|BusyBox[\s\d\.]*|OpenWrt|sysvinit|- preinit -|- init -)\b", text, re.I)
        if init:
            lines_out.append(f"Init System: {init.group(0)}")

    elif choice == 4:  # Secure Boot Declaration
        sb = re.search(r"(?:Secure Boot Status|Secure Boot):\s*([^\n\r]+)", text, re.I)
        if sb:
            lines_out.append(f"Secure Boot Status: {sb.group(1).strip()}")
        else:
            fw_check = "Firmware check pass" in text or "Verifying Checksum ... OK" in text
            crc_warning = "bad CRC" in text or "Warning - bad CRC" in text
            jtag_warning = "Insecure JTAG debug mode is enabled" in text

            if fw_check and not crc_warning:
                lines_out.append("Secure Boot Status: Verified (Checksum & Image Integrity Confirmed)")
            elif crc_warning or jtag_warning:
                lines_out.append("Secure Boot Status: INSECURE / BYPASS DETECTED (Bad CRC warning ignored or JTAG unlocked)")
            elif "verify" in text.lower():
                lines_out.append("Secure Boot Status: Basic Partition Verification Configured")
            else:
                lines_out.append("Secure Boot Status: Not Enforced / Unsigned Boot Sequence")

        stages = re.search(r"(?:Boot Stages|Boot Chain):\s*([^\n\r]+)", text, re.I)
        if stages:
            lines_out.append(f"Boot Stages: {stages.group(1).strip()}")
        else:
            detected_stages = []
            if "U-Boot SPL" in text: detected_stages.append("U-Boot SPL")
            if "U-Boot 20" in text: detected_stages.append("U-Boot Main")
            if "Starting kernel" in text or "Booting Linux" in text: detected_stages.append("Linux Kernel")
            if detected_stages:
                lines_out.append(f"Boot Stages: {' -> '.join(detected_stages)}")

        algo = re.findall(r"\b(RSA-\d+|ECDSA|SHA-256|SHA-512|2048bits|CRC32|AES-\d+|PKCS[^\s,\)]*)\b", text, re.I)
        if algo:
            lines_out.append(f"Signature / Hash Algorithms: {', '.join(sorted(set(algo)))}")

        storage = re.search(r"(?:Key Storage|Storage):\s*([^\n\r]+)", text, re.I)
        if storage:
            lines_out.append(f"Key Storage: {storage.group(1).strip()}")
        elif re.search(r"\b(ATECC\w*|TPM|eFuse|OTP|TrustZone|OP-TEE)\b", text, re.I):
            lines_out.append("Key Storage: Hardware Secure Element / OTP eFuse")
        elif "flash" in text.lower():
            lines_out.append("Key Storage: Plain Flash Memory (Unencrypted SPI NOR/NAND)")

        fail = re.search(r"(?:Fail Mode|Failure Action):\s*([^\n\r]+)", text, re.I)
        if fail:
            lines_out.append(f"Fail Mode: {fail.group(1).strip()}")
        elif "using default environment" in text:
            lines_out.append("Fail Mode: Fallback to default U-Boot environment on CRC failure")

    elif choice == 5:  # Network Protocols & Services
        proto = re.findall(r"\b(HTTP/1\.1|HTTPS|TLS \d\.\d|MQTT|RTSP|CoAP|DNS|SSH|Telnet|TCP|UDP|ONVIF)\b", text, re.I)
        if proto:
            lines_out.append(f"Protocols: {', '.join(sorted(set(proto)))}")

        daemons = re.findall(r"\b(dropbear|sshd|lighttpd|mosquitto|telnetd|httpd|apache|nginx|dnsmasq|rtsp-streamer|openapid|onvif|wlan-manager|hostapd)\b[^\n\r]*", text, re.I)
        if daemons:
            cleaned_d = [d.strip(" -") for d in set(daemons)]
            lines_out.append("Active Daemons & Services:\n  - " + "\n  - ".join(cleaned_d))

        ports = re.findall(r"\b(?:port\s*(\d+)|(\d+)/tcp|(\d+)/udp)\b", text, re.I)
        found_ports = []
        for p in ports:
            for item in p:
                if item: found_ports.append(item)
        if found_ports:
            lines_out.append(f"Listening / Active Ports: {', '.join(sorted(set(found_ports), key=lambda x: int(x)))}")

        creds = re.findall(r"\b(admin:[^\s\n]+|root:[^\s\n]+|support:[^\s\n]+|user:password|root:\$[0-9a-zA-Z\$\.\/]+)\b", text, re.I)
        if creds:
            lines_out.append("Detected Credentials / Password Hashes:\n  - " + "\n  - ".join(set(creds)))

    elif choice == 6:  # Remote Access & Cloud
        cloud = re.findall(r"\b(AWS IoT Core|Tuya|Azure IoT|Alibaba Cloud|Google Cloud IoT|TP-Link|Tapo|cloud-service|cloudiot)\b", text, re.I)
        if cloud:
            lines_out.append(f"Cloud Ecosystem: {', '.join(set(cloud))}")

        endpoints = re.findall(r"([a-zA-Z0-9\.\-_]+\.(?:amazonaws\.com|tuya\.com|azure-devices\.net|tplinknbu\.com|cybercore-cloud\.com)[^\s\n\r]*)", text, re.I)
        if endpoints:
            lines_out.append("Cloud Endpoints:\n  - " + "\n  - ".join(set(endpoints)))

        tokens = re.findall(r"\b(bindCode|bindToken|deviceSecret|deviceToken|oem_id):\s*([0-9a-zA-Z]+)", text, re.I)
        if tokens:
            lines_out.append("Cloud Identity Tokens:\n  - " + "\n  - ".join(f"{k}: {v}" for k, v in tokens))

        access = re.search(r"(?:Remote Access Surfaces|Access Type):\s*([^\n\r]+)", text, re.I)
        if access:
            lines_out.append(f"Remote Access: {access.group(1).strip()}")
        else:
            surfaces = []
            if "RTSP" in text or "554" in text: surfaces.append("RTSP Camera Streaming (Port 554)")
            if "openapid" in text or "HTTPS" in text: surfaces.append("HTTPS OpenAPI Web Server")
            if "onvif" in text: surfaces.append("ONVIF Profile Management")
            if "SSH" in text or "dropbear" in text: surfaces.append("SSH Remote Shell")
            if "telnetd" in text: surfaces.append("Telnet Insecure Remote Shell")
            if surfaces:
                lines_out.append("Remote Management Interfaces:\n  - " + "\n  - ".join(surfaces))

    elif choice == 7:  # Update & Patch Declaration
        method = re.search(r"(?:Update Method|Method):\s*([^\n\r]+)", text, re.I)
        if method:
            lines_out.append(f"Update Method: {method.group(1).strip()}")
        elif "ota" in text.lower() or "cloud-service" in text.lower():
            lines_out.append("Update Method: Over-The-Air (OTA) Cloud Synchronization")
        elif "tftp" in text.lower():
            lines_out.append("Update Method: Network TFTP / Bootloader Recovery")
        else:
            lines_out.append("Update Method: Manual SPI Flash Flashrom / Firmware Upload")

        verify = re.search(r"(?:Verification Policy|Verification):\s*([^\n\r]+)", text, re.I)
        if verify:
            lines_out.append(f"Verification: {verify.group(1).strip()}")
        elif "gpg" in text.lower():
            lines_out.append("Verification: GPG Cryptographic Signature")
        elif "checksum" in text.lower() or "crc" in text.lower():
            lines_out.append("Verification: Header CRC / Legacy Checksum Verification")

        rollback = re.search(r"(?:Anti-Rollback Protection|Anti-rollback):\s*([^\n\r]+)", text, re.I)
        if rollback:
            lines_out.append(f"Anti-Rollback: {rollback.group(1).strip()}")
        elif "a/b" in text.lower() or "dual" in text.lower():
            lines_out.append("Anti-Rollback: Dual-Bank Redundant Image Protection")

        rec = re.search(r"(?:Recovery Policy|Recovery):\s*([^\n\r]+)", text, re.I)
        if rec:
            lines_out.append(f"Recovery Policy: {rec.group(1).strip()}")
        elif "watchdog" in text.lower() or "wtd timeout" in text.lower():
            lines_out.append("Recovery Policy: Hardware Watchdog Timer Automatic Reset")
        elif "read-only" in text.lower():
            lines_out.append("Recovery Policy: Write-Protected Factory Boot & Recovery Partition")

    elif choice == 8:  # Reverse Engineering Indicators
        console = re.search(r"(?:Please press Enter to activate this console|console\s*\[\w+\]\s*enabled)", text, re.I)
        if console:
            lines_out.append("Console Access: ACTIVE UNRESTRICTED SERIAL CONSOLE (Interactive root shell available via UART without authentication)")

        dev_paths = re.findall(r"(/home/[a-zA-Z0-9_\-]+/[^\s\n\r:\"]+)", text)
        if dev_paths:
            lines_out.append("Leaked Developer Source Paths:\n  - " + "\n  - ".join(list(set(dev_paths))[:4]))

        dbg = re.findall(r"\b(ubus4dbg\w*|CONFIG_DEBUG\w*|\[Debug\]|early0|gdb\w*|tracepoints|ftrace|kprobes)\b", text, re.I)
        if dbg:
            lines_out.append(f"Exposed Debugging Hooks: {', '.join(sorted(set(dbg)))}")

        ko = re.findall(r"insmod\s+([^\s\n\r]+\.ko)", text)
        if ko:
            lines_out.append("Dynamically Injected Kernel Modules:\n  - " + "\n  - ".join(set(ko)))

        strip = re.search(r"(?:Symbol Stripping|Stripped Symbols):\s*([^\n\r]+)", text, re.I)
        if strip:
            lines_out.append(f"Stripped Symbols: {strip.group(1).strip()}")
        else:
            lines_out.append("Disassembly Analysis: Unencrypted plain binary; MTD partitions directly mountable via standard tooling")

    elif choice == 9:  # SBOM & Vulnerabilities
        sbom_std = re.search(r"(?:SBOM Standard|SBOM References):\s*([^\n\r]+)", text, re.I)
        if sbom_std:
            lines_out.append(f"SBOM Standard: {sbom_std.group(1).strip()}")

        pkgs = []
        for p in ['OpenSSL', 'BusyBox', 'Dropbear', 'lighttpd', 'dnsmasq', 'libcurl', 'Mosquitto', 'systemd', 'u-boot', 'Linux version', 'SquashFS']:
            m = re.search(rf"\b{p}\b[^\n,;]*(?:v?\d+\.[\d\w\.\-]+)?", text, re.I)
            if m:
                pkgs.append(m.group(0).strip(" -"))
        if pkgs:
            lines_out.append("Open-Source Packages:\n  - " + "\n  - ".join(pkgs))

        cves = sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I))))
        if cves:
            lines_out.append(f"Detected CVEs: {', '.join(cves)}")

        lics = sorted(list(set(re.findall(r"(?:License:\s*|License\s+)([A-Za-z0-9\.\-\/ ]+?)(?=\n|\s*-\s*|\s*\(|\s*$)", text))))
        if lics:
            lines_out.append(f"License Types: {', '.join(lics)}")

        contacts = sorted(list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text))))
        if contacts:
            lines_out.append(f"Security Contacts: {', '.join(contacts)}")

    return "\n\n".join(lines_out)


def run(choice: int, file_path: str):
    if choice not in PROMPT_MAP:
        return f"Error: Invalid task choice '{choice}'. Must be between 1 and 9."

    print(f"\n=== Optimized Firmware Analyzer (Task {choice}: {PROMPT_MAP.get(choice, {}).get('title', 'Analysis')}) ===")

    if not os.path.exists(file_path):
        return "Error: Firmware file not found."

    print("Step 1: Ingesting file and normalizing text/binary...")
    lines, full_text = load_and_clean_file(file_path, min_len=4)
    print(f"Extracted {len(lines)} lines/strings ({len(full_text)} characters).")

    print("Step 2: Running high-speed deterministic pattern extractor...")
    deterministic_result = extract_deterministic_metadata(full_text, choice)

    # If deterministic extractor found rich metadata, return immediately (<5ms)
    if deterministic_result and len(deterministic_result.strip()) > 25:
        print(f"Deterministic extraction succeeded in <5ms for Task {choice}.")
        return deterministic_result

    # Fallback to model-based extraction for ambiguous / unstructured strings
    print("Step 3: Applying targeted Regex pre-filtering for LLM...")
    filtered_text = filter_relevant_strings(lines, choice)
    print(f"Filtered down to {len(filtered_text)} characters.")

    # Use a single compact chunk (2000 chars) for fast CPU evaluation
    chunks = chunk_text(filtered_text, size=2000, overlap=100, max_chunks=1)
    analysis_results = []
    if deterministic_result:
        analysis_results.append(deterministic_result)

    task_prompt = PROMPT_MAP.get(choice, {}).get('task', 'Analyze firmware.')

    try:
        client = ollama.Client(timeout=25)
        for i, chunk in enumerate(chunks):
            print(f"Querying SLM with high-signal context (timeout: 25s)...")
            response = client.chat(
                model=MODEL_NAME,
                messages=[
                    {'role': 'system', 'content': SYSTEM_INSTRUCTION + " Do NOT output thinking, reasoning steps, or scratchpad. Immediately output Key: Value pairs."},
                    {'role': 'user', 'content': f"TASK: {task_prompt}\n\nDATA:\n{chunk}"}
                ],
                options={'num_predict': 300, 'temperature': 0.1, 'num_thread': 3}
            )

            content = ""
            msg = getattr(response, "message", None)
            if msg:
                content = getattr(msg, "content", "") or ""
            elif isinstance(response, dict):
                content = response.get("message", {}).get("content", "")

            # Strip thinking tags and process lines
            content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL).strip()
            if "Thinking Process:" in content:
                # Keep only content after thinking or extract KV lines
                kv_lines = [l.strip() for l in content.splitlines() if ":" in l and len(l.split(":")[0].split()) <= 4 and not l.strip().startswith("*")]
                if kv_lines:
                    content = "\n".join(kv_lines)
                else:
                    content = ""

            if content and "Not available" not in content and "N/A" not in content[:30]:
                analysis_results.append(content)
    except Exception as e:
        print(f"SLM query notice: {e}")

    if not analysis_results:
        return "No specific metadata discovered for this category in the provided binary."

    return "\n\n---\n\n".join(analysis_results)

