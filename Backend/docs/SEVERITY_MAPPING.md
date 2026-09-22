# FirmAudit: Security Audit Severity Scoring & Rule Mapping Guide

This document defines the severity scoring methodology, classification logic, and technical rule mapping for **FirmAudit** (the static firmware binary and filesystem security analysis tool developed at the IoT Security Research Lab, IIIT Allahabad).

FirmAudit inspects unpacked embedded Linux firmware images (SquashFS, CramFS, JFFS2, UBIFS), ELF binaries, kernel modules (`.ko`), system startup scripts, and configuration stores.

---

## 1. FirmAudit Severity Scoring & Rule Mapping Table

| Finding Category | FirmAudit Finding / Pattern | Severity Level | UI Badge Color | Risk Rationale & Impact | Heuristic / Detection Logic (`FirmAudit.py`) |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **Vulnerabilities** | `Command Injection` | <span style="background-color:#DC2626;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">CRITICAL</span> | Red (`#DC2626`) | Unsanitized user parameters passed directly to shell execution functions (`system()`, `popen()`, `exec()`, `passthru()`, `shell_exec()`) in web interfaces or CGI scripts. Leads directly to unauthenticated remote root shell access. | `search_command_injection()` regex scan matching `system\s*\(`, `popen\s*\(`, `exec\s*\(`, `shell_exec\s*\(` across web handlers. |
| **Vulnerabilities** | `Hardcoded SSH Private Key` | <span style="background-color:#DC2626;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">CRITICAL</span> | Red (`#DC2626`) | Embedded private cryptographic keys (RSA, DSA, EC) baked into firmware binaries or config stores. Enables unauthorized SSH login, cryptographic impersonation, and eavesdropping/decryption of encrypted management traffic. | `search_hardcoded_ssh_keys()` regex matching `-----BEGIN (RSA\|DSA\|EC) PRIVATE KEY-----` headers. |
| **Vulnerabilities** | `Dangerous Function (sprintf)` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Unbounded string formatting function in compiled ELF executables or `.ko` kernel modules. Susceptible to stack buffer overflows and format-string memory corruption attacks. | `identify_dangerous_functions()` parsing `.symtab` / `.dynsym` symbol tables using `pyelftools` for `sprintf`. |
| **Vulnerabilities** | `Dangerous Function (strcpy, gets, strcat, scanf)` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Legacy C runtime APIs lacking buffer boundary checks. Exploitable for control-flow hijacking, return-oriented programming (ROP), and arbitrary code execution. | `identify_dangerous_functions()` matching symbol tables against banned API list (`strcpy`, `gets`, `strcat`, `scanf`). |
| **Credentials** | `Password / Shadow Hash File` | <span style="background-color:#DC2626;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">CRITICAL</span> | Red (`#DC2626`) | Static `/etc/shadow` or `/etc/passwd` containing pre-computed root/admin password hashes (DES, MD5, SHA-512 crypt). Allows offline GPU cracking (Hashcat/John) or pass-the-hash attacks. | `file_search()` matching filename patterns `passwd`, `shadow`, or `*.psk` in the filesystem. |
| **Credentials** | `Default Credentials in Config/Script` | <span style="background-color:#DC2626;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">CRITICAL</span> | Red (`#DC2626`) | Embedded plaintext admin credentials in startup scripts (`/etc/init.d/`, `rc.local`, `.sh`, `.conf`, `.json`). Grants immediate privileged device access upon initial network connection. | `search_default_credentials()` with path heuristic checking `/etc/`, `.conf`, `.cfg`, `.sh`, `init`, `rc.`. |
| **Credentials** | `Default Credentials in Daemon Binary` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Hardcoded fallback account credentials (`admin:admin`, `root:root`, etc.) compiled into network service daemons (`dropbear`, `telnetd`, `login`, `ftpd`, `updater`). | String pattern scan on daemons (`dropbear`, `telnetd`, `ftpd`, `login`); filtered to exclude BusyBox helper applets. |
| **Credentials** | `Default Credentials in General Binary` | <span style="background-color:#D97706;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">MEDIUM</span> | Amber (`#D97706`) | Default credential strings found in secondary utilities or diagnostic tools that may not be directly reachable from external interfaces. | String search for default pairs (`admin/admin`, `root/root`, `admin/password`) across generic binaries. |
| **Weak Crypto** | `Broken Cipher (DES, RC4)` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Cryptographically obsolete ciphers. DES uses a 56-bit key space brute-forceable in hours; RC4 contains severe statistical keystream biases enabling plaintext recovery. | `search_weak_cryptographic_algorithms()` regex matching `\bDES\b(?!sum)` and `\bRC4\b`. |
| **Weak Crypto** | `Predictable Key Pattern` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Static, default, or low-entropy encryption keys (e.g., `key="12345678"`, repeating bytes) hardcoded in binary code or configuration files. | `search_weak_keys()` regex matching `key\s*=\s*['"]?[a-zA-Z0-9]{8,16}['"]?` and static passwords. |
| **Weak Crypto** | `Deprecated Hashing (MD5, SHA1)` | <span style="background-color:#D97706;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">MEDIUM</span> | Amber (`#D97706`) | Collision-prone hashing algorithms. Inadequate for certificate verification, digital signatures, or HMAC authentication due to practical collision exploits. | `search_weak_cryptographic_algorithms()` regex matching `\bMD5\b(?!sum)` and `\bSHA1\b(?!sum)`. |
| **Sensitive Stores** | `SSL Private Key / Certificate` | <span style="background-color:#EA580C;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">HIGH</span> | Orange (`#EA580C`) | Pre-packaged SSL/TLS private keys (`*.key`, `*.pem`, `*.p12`) sharing identities across devices, enabling man-in-the-middle (MITM) inspection of HTTPS sessions. | `file_search()` scanning extensions `*.crt`, `*.pem`, `*.cer`, `*.p7b`, `*.p12`, `*.key`. |
| **Sensitive Stores** | `Database Storage File` | <span style="background-color:#D97706;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">MEDIUM</span> | Amber (`#D97706`) | Embedded SQLite databases (`*.db`, `*.sqlite`, `*.sqlite3`) potentially storing user accounts, device configurations, network topology, or cached credentials. | `file_search()` scanning extensions `*.db`, `*.sqlite`, `*.sqlite3`. |
| **Sensitive Stores** | `System Configuration File` | <span style="background-color:#2563EB;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">LOW</span> | Blue (`#2563EB`) | System configuration stores (`*.conf`, `*.cfg`, `*.ini`) defining daemon behaviors, network routing, and authentication parameters. | `file_search()` scanning extensions `*.conf`, `*.cfg`, `*.ini`. |
| **Sensitive Stores** | `Critical Service Binary` | <span style="background-color:#2563EB;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">LOW</span> | Blue (`#2563EB`) | Core daemon binaries (`sshd`, `dropbear`, `telnetd`, `httpd`, `openssl`) present in the filesystem. Identifies active attack surfaces. | `file_search()` matching `ssh`, `dropbear`, `telnet`, `openssl`, etc. |
| **Network Endpoints** | `Hardcoded IPv4 Address` | <span style="background-color:#2563EB;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">LOW / INFO</span> | Blue (`#2563EB`) | Hardcoded IP addresses embedded in scripts or binaries. Indicates backend management servers, NTP servers, or potential command-and-control (C2) hosts. | `ip_Search()` matching IPv4 patterns `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`. |
| **Network Endpoints** | `Hardcoded URL Endpoint` | <span style="background-color:#2563EB;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">LOW / INFO</span> | Blue (`#2563EB`) | Discovered HTTP/HTTPS URLs pointing to vendor firmware update servers, remote APIs, telemetry endpoints, or external resources. | `url_search()` matching standard URI schemas `http[s]?://...`. |
| **Network Endpoints** | `Developer Email Contact` | <span style="background-color:#2563EB;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">LOW / INFO</span> | Blue (`#2563EB`) | Developer or vendor support email addresses found in binaries, licenses, or scripts. Useful for developer profiling and supply chain analysis. | `pattern_search()` using standard RFC email regular expression. |
| **Dependencies** | `Dynamic Library Dependency` | <span style="background-color:#64748B;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">INFO</span> | Slate (`#64748B`) | Shared library requirements (`DT_NEEDED` segment) extracted from ELF headers. Used to evaluate outdated third-party library dependencies (e.g., old OpenSSL, uClibc). | `identify_third_party_libraries()` reading `PT_DYNAMIC` header tags via `pyelftools`. |
| **Signatures** | `File Magic Signature` | <span style="background-color:#64748B;color:#ffffff;padding:2px 8px;border-radius:4px;font-weight:bold;font-size:12px">INFO</span> | Slate (`#64748B`) | Magic byte header verification (ELF, gzip, bzip2, PNG, JPEG, PE, etc.) for verifying file integrity and detecting obfuscated or disguised binaries. | `identify_file_signatures()` reading first 64 bytes of files and matching header signatures. |

---

## 2. FirmAudit Calculation & Classification Logic

The scoring engine in `Backend/firmaudit_parser.py` (and the mirror parser in `FirmwareCommon.js`) applies deterministic criteria to convert raw text output into structured findings:

```
                  ┌─────────────────────────────────────┐
                  │    FirmAudit Unpacked Filesystem    │
                  └──────────────────┬──────────────────┘
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           ▼                         ▼                         ▼
   [ELF Symbol Table]      [Cryptographic Assets]     [Filesystem & Scripts]
   • sprintf, strcpy       • SSH Private Keys         • /etc/shadow, passwd
   • system, popen         • DES / RC4 ciphers        • Config credentials
   • DT_NEEDED libraries   • Predictable keys         • Daemon binaries
           │                         │                         │
           └─────────────────────────┼─────────────────────────┘
                                     ▼
                   ┌───────────────────────────────────┐
                   │     firmaudit_parser Engine       │
                   └─────────────────┬─────────────────┘
                                     │
         ┌──────────────┬────────────┴───┬──────────────┬──────────────┐
         ▼              ▼                ▼              ▼              ▼
    CRITICAL           HIGH            MEDIUM          LOW            INFO
  • Cmd Injection  • Dangerous API  • MD5 / SHA1   • IP Addrs    • DT_NEEDED
  • SSH Keys       • Broken Cipher  • Generic Cred • URLs        • File Magic
  • Shadow Hashes  • Static Key     • DB Files     • System Conf
  • Config Creds   • Daemon Creds
```

### Classification Heuristics:

1. **CRITICAL Severity**:
   - **Condition**: Finding enables immediate unauthenticated administrative access or exposes root secrets.
   - **Rules**:
     - `type == "Command Injection"`: Shell execution vector in web interface / CGI script.
     - `type == "Hardcoded SSH Private Key"`: Device-wide RSA/DSA/EC private keys.
     - `type == "Password / Shadow Hash File"`: Direct `/etc/shadow` or password hash file.
     - `type == "Default Credentials in Config/Script"`: Plaintext admin credentials in `/etc/`, `.conf`, `.cfg`, or startup `.sh` scripts.

2. **HIGH Severity**:
   - **Condition**: Finding provides a memory-corruption primitive or severely compromised cryptography.
   - **Rules**:
     - `type.startswith("Dangerous Function")`: Memory-unsafe functions (`sprintf`, `strcpy`, `system`, `gets`, `strcat`, `scanf`) found in ELF symbol tables.
     - `algorithm in ["DES", "RC4"]`: Cryptographically broken symmetric ciphers.
     - `algorithm == "Predictable Key Pattern"`: Static or low-entropy encryption keys.
     - `type == "Default Credentials in Daemon Binary"`: Credentials identified inside network daemons (`dropbear`, `telnetd`, `login`, `ftpd`, `updater`).

3. **MEDIUM Severity**:
   - **Condition**: Deprecated security mechanisms or findings requiring contextual privilege.
   - **Rules**:
     - `algorithm in ["MD5", "SHA1"]`: Collision-vulnerable hash functions.
     - `type == "Default Credentials in Binary"`: Credential strings in non-daemon utilities.
     - Database files (`*.db`, `*.sqlite`) storing application state.

4. **LOW / INFORMATIONAL Severity**:
   - **Condition**: Reconnaissance, telemetry, or structural architecture information.
   - **Rules**:
     - Discovered IPv4 addresses, remote URLs, and developer emails.
     - ELF `DT_NEEDED` shared library linkages.
     - Binary file magic signatures.

---

## 3. Frontend Visualization Reference (`FirmAuditReportView.js`)

In the firmware analysis dashboard, findings are color-coded:

| Severity Level | Background Color | Text Color | Typography / Style |
| :--- | :---: | :---: | :--- |
| **CRITICAL** | `#DC2626` (Red) | `#FFFFFF` | Solid filled pill badge, bold (`font-weight: 700`) |
| **HIGH** | `#EA580C` (Orange) | `#FFFFFF` | Solid filled pill badge, bold (`font-weight: 700`) |
| **MEDIUM** | `#D97706` (Amber) | `#FFFFFF` | Solid filled pill badge, bold (`font-weight: 700`) |
| **LOW** | `#2563EB` (Blue) | `#FFFFFF` | Solid filled pill badge, bold (`font-weight: 700`) |
| **INFO** | `#64748B` (Slate) | `#FFFFFF` | Solid filled pill badge, bold (`font-weight: 700`) |

---

## 4. FirmAudit Remediation Guide

1. **Dangerous Memory APIs (`sprintf`, `strcpy`)**: Replace with bounded functions (`snprintf`, `strncpy`, or `strlcpy`). Compile with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=2`.
2. **Hardcoded SSH Private Keys**: Remove embedded key pairs from rootfs. Generate unique host keys on initial device boot using `/etc/init.d/dropbear` or hardware TRNG.
3. **Hardcoded Credentials & Hashes**: Disallow static root passwords in `/etc/shadow`. Enforce a mandatory setup wizard requiring user password configuration on first login.
4. **Weak Cryptography**: Deprecate DES, RC4, MD5, and SHA1. Migrate all symmetric operations to AES-GCM (128/256-bit) or ChaCha20-Poly1305, and hashes to SHA-256 / SHA-512.
