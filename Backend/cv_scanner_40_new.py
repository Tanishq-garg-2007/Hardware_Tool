
"""
Bootlog CVE Scanner — with Integrated CVE JSON 5.0 Sync
-------------------------------------------------------
Automatically keeps the CVE database current using the cvelistV5 repository, 
then scans a UART/serial bootlog for matching CVEs in two passes.

  SYNC  — Smart database download/update:
    • Downloads `main.zip` from CVEProject/cvelistV5
    • Extracts and parses CVE JSON 5.0 format into a local cache

  SCAN 1 — Bootloader / Firmware CVEs
    • Bootloader version  → CVE database (U-Boot, GRUB, Barebox...)
    • Additional firmware: OpenSBI, ATF BL31, OP-TEE, GRUB, Barebox
    • Component & filesystem cross-check (MMC, USB, SPI, NAND, FAT …)
    • CPU architecture filter (ARM / x86 / MIPS / RISC-V / PowerPC)

  SCAN 2 — Linux Kernel + Userspace Tools
    • Linux kernel version → subsystem CVEs
    • SquashFS, fuse-exfat, GCC, TF-A, BusyBox, OpenSSL, mbed TLS

Usage:
    python finalbootloagscanner.py
    python finalbootloagscanner.py --file cves.json
    python finalbootloagscanner.py --file cves.json --dry-run
"""

# =============================================================================
# IMPORTS
# =============================================================================

import argparse
import json
import lzma
import logging
import os
import re
import sys
import time
import urllib.error
from dataclasses import dataclass, field


from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from packaging.version import Version, InvalidVersion
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# =============================================================================
# SECTION 0: SYNC — CVE JSON 5.0 (cvelistV5)
# =============================================================================

import shutil
import zipfile
import datetime

def should_update() -> bool:
    try:
        from cve_updater import check_should_update, is_internet_available
        # OFFLINE FIRST: If no internet connection, NEVER update/download
        if not is_internet_available():
            return False
        return check_should_update()["needs_update"]
    except Exception:
        return False

def update() -> bool:
    try:
        from cve_updater import _download_and_extract_task, is_internet_available
        if not is_internet_available():
            log.info("Offline mode: No internet connection detected, skipping update.")
            return False
        print("\n[+] Triggering NIST NVD Database download and sync...")
        _download_and_extract_task(force=True)
        return True
    except Exception as e:
        log.error(f"Error occurred while updating NVD database: {str(e)}")
        return False


# =============================================================================
# TOOL BANNER
# =============================================================================

TOOL_BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║    Bootlog CVE Vulnerability Scanner — Sync + Dual-Stage Edition           ║
║                                                                              ║
║  SYNC  — Automatic NVD Database Management                                 ║
║    • No file found  →  Full download via Fraunhofer FKIE mirror            ║
║    • File exists    →  Incremental update (only new/changed CVEs)          ║
║                                                                              ║
║  SCAN 1 — Bootloader / Firmware                                             ║
║    • Bootloader version  →  NVD CVE database (U-Boot, GRUB, Barebox...)    ║
║    • Additional firmware: OpenSBI, ATF BL31, OP-TEE, GRUB, Barebox        ║
║    • Component & filesystem cross-check (MMC, USB, SPI, NAND, FAT …)      ║
║    • CPU architecture filter (ARM / x86 / MIPS / RISC-V / PowerPC)        ║
║                                                                              ║
║  SCAN 2 — Linux Kernel + Userspace Tools                                   ║
║    • Linux kernel version  →  subsystem CVEs (commit-prefix detection)     ║
║    • SquashFS, fuse-exfat, GCC, TF-A, BusyBox, OpenSSL, mbed TLS         ║
║                                                                              ║
║  Usage:  python merged_bootlog_cve_scanner.py [--file cves.json]           ║
║  Input:  UART / serial bootlog (.txt)  +  NVD JSON database               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# =============================================================================
# SECTION 1: DATACLASSES
# =============================================================================

@dataclass
class BootlogInfo:
    """Structured representation of parameters extracted from a U-Boot bootlog."""
    bootloader_version: str = ""
    bootloader_full_string: str = ""
    bootloader_suffix: str = ""
    spl_version: str = ""
    cpu_raw: str = ""
    cpu_keywords: set = field(default_factory=set)
    cpu_architecture: str = ""
    model_raw: str = ""
    filesystems: set = field(default_factory=set)
    file_formats: set = field(default_factory=set)
    crypto_algos: set = field(default_factory=set)
    additional_firmware: dict = field(default_factory=dict)
    kernel_version: str = ""
    kernel_build_date: str = ""
    squashfs_version: str = ""
    fuse_exfat_version: str = ""
    gcc_version: str = ""
    tfa_version: str = ""
    busybox_version: str = ""
    busybox_behavior: bool = False
    openssl_version: str = ""
    mbedtls_version: str = ""
    mbedtls_behavior: bool = False
    detected_vendors: set = field(default_factory=set)
    failed_features: dict = field(default_factory=dict)
    initialized_drivers: set = field(default_factory=set)
    kernel_subsystems: set = field(default_factory=set)
    leaked_secrets: list = field(default_factory=list)
    raw_log: str = ""

    def summary(self) -> str:
        lines = []
        lines.append(f"  Bootloader:    {self.bootloader_full_string or 'Not found'}")
        lines.append(f"  Version:       {self.bootloader_version or 'Not found'}")
        if self.spl_version:
            lines.append(f"  SPL Version:   {self.spl_version}")
        lines.append(f"  CPU/SoC:       {self.cpu_raw or 'Not found'}")
        lines.append(f"  Architecture:  {self.cpu_architecture or 'Unknown'}")
        if self.model_raw:
            lines.append(f"  Model:         {self.model_raw}")
        lines.append(f"  Filesystems:   {', '.join(sorted(self.filesystems)) or 'None detected'}")
        lines.append(f"  File Formats:  {', '.join(sorted(self.file_formats)) or 'None detected'}")
        if self.additional_firmware:
            for fw_name, fw_ver in self.additional_firmware.items():
                lines.append(f"  {fw_name.upper():14s} {fw_ver}")
        if self.kernel_version:
            lines.append(f"  Kernel:        {self.kernel_version}")
        if self.squashfs_version:
            lines.append(f"  SquashFS:      {self.squashfs_version}")
        if self.fuse_exfat_version:
            lines.append(f"  fuse-exfat:    {self.fuse_exfat_version}")
        if self.gcc_version:
            lines.append(f"  GCC:           {self.gcc_version}")
        if self.busybox_version:
            lines.append(f"  BusyBox:       {self.busybox_version}")
        elif self.busybox_behavior:
            lines.append(f"  BusyBox:       Detected (Behavioral)")
        if self.openssl_version:
            lines.append(f"  OpenSSL:       {self.openssl_version}")
        if self.mbedtls_version:
            lines.append(f"  mbed TLS:      {self.mbedtls_version}")
        elif self.mbedtls_behavior:
            lines.append(f"  mbed TLS:      Detected (Behavioral)")
        if self.initialized_drivers:
            init_str = ", ".join(sorted(list(self.initialized_drivers))[:5])
            if len(self.initialized_drivers) > 5: init_str += "..."
            lines.append(f"  Init Drivers:  {init_str}")
        if self.kernel_subsystems:
            lines.append(f"  Kern Subsys:   {', '.join(sorted(self.kernel_subsystems))}")
        return "\n".join(lines)


@dataclass
class CVEMatch:
    """Represents a CVE that matched the bootlog parameters."""
    cve_id: str = ""
    description: str = ""
    severity: str = ""
    base_score: float = 0.0
    published: str = ""
    last_modified: str = ""
    matched_product: str = ""
    matched_vendor: str = ""
    matched_version_range: str = ""
    matched_components: list = field(default_factory=list)
    match_stage: str = ""
    cpu_filter_result: str = ""
    cpu_details: str = ""
    references: list = field(default_factory=list)
    weaknesses: list = field(default_factory=list)
    scan: int = 1
    subsystem: str = ""
    date_risk: dict = field(default_factory=dict)
    feature_proof: str = ""


# =============================================================================
# SECTION 2: ARCHITECTURE & PRODUCT MAPS
# =============================================================================

_ARCH_KEYWORD_MAP = {
    "arm": "arm", "aarch64": "arm", "armv7": "arm", "armv8": "arm",
    "cortex": "arm", "cortex-a": "arm", "cortex-m": "arm", "cortex-r": "arm",
    "i.mx": "arm", "imx": "arm", "stm32": "arm", "am335": "arm", "am33xx": "arm",
    "am57": "arm", "omap": "arm", "sunxi": "arm", "sun8i": "arm", "sun50i": "arm",
    "allwinner": "arm", "rk3": "arm", "rockchip": "arm", "zynq": "arm",
    "zynqmp": "arm", "exynos": "arm", "socfpga": "arm", "tegra": "arm",
    "versal": "arm", "snapdragon": "arm", "xburst": "mips", "ingenic": "mips",
    "x86": "x86", "x86_64": "x86", "amd64": "x86", "i386": "x86",
    "i686": "x86", "intel": "x86", "atom": "x86", "baytrail": "x86",
    "mips": "mips", "mips32": "mips", "mips64": "mips", "mt7621": "mips",
    "mt7620": "mips", "ar9": "mips", "qca9": "mips", "ath79": "mips",
    "octeon": "mips", "t31": "mips", "t20": "mips", "t10": "mips",
    "risc-v": "riscv", "riscv": "riscv", "rv32": "riscv", "rv64": "riscv",
    "sifive": "riscv", "starfive": "riscv", "thead": "riscv", "jh71": "riscv",
    "fu540": "riscv", "fu740": "riscv",
    "powerpc": "powerpc", "ppc": "powerpc", "mpc8": "powerpc",
    "p1010": "powerpc", "p2020": "powerpc", "qoriq": "powerpc",
}

ARCH_FAMILIES = {
    "arm": [
        "arm", "aarch64", "armv7", "armv8", "arm64", "arm-based",
        "cortex-a", "cortex-m", "cortex-r",
        "i.mx", "imx", "stm32", "am335", "am33xx", "am57",
        "omap", "exynos", "zynq", "zynqmp",
        "allwinner", "sunxi", "sun8i", "sun50i",
        "rockchip", "rk3", "tegra", "socfpga", "versal", "snapdragon",
    ],
    "x86": [
        "x86", "x86_64", "x86-64", "amd64", "i386", "i686",
        "intel", "atom", "baytrail", "ia-32", "ia32", "x86-based",
    ],
    "mips": [
        "mips", "mips32", "mips64", "mipsel", "mips-based",
        "mt7621", "mt7620", "ar9", "qca9", "ath79", "octeon",
        "xburst", "ingenic", "t31", "t20", "t10",
    ],
    "riscv": [
        "risc-v", "riscv", "rv32", "rv64", "risc-v-based",
        "sifive", "starfive", "thead", "jh71",
    ],
    "powerpc": [
        "powerpc", "ppc", "power pc", "powerpc-based",
        "mpc8", "p1010", "p2020", "qoriq", "e500",
    ],
}

KNOWN_PRODUCTS = {
    "u-boot":       ("denx",           "u-boot"),
    "opensbi":      ("opensbi",        "opensbi"),
    "atf_bl31":     ("arm",            "trusted_firmware-a"),
    "optee":        ("op-tee",         "op-tee_os"),
    "linux_kernel": ("linux",          "linux_kernel"),
    "ubifs":        ("linux",          "linux_kernel"),
    "ext4":         ("linux",          "linux_kernel"),
    "squashfs":     ("linux",          "linux_kernel"),
    "grub":         ("gnu",            "grub2"),
    "barebox":      ("barebox_project","barebox"),
    "coreboot":     ("coreboot",       "coreboot"),
}

SCAN2_PRODUCTS = {
    "dm_crypt":       ("linux", "linux_kernel"),
    "dm_verity":      ("linux", "linux_kernel"),
    "fs_mgr":         ("linux", "linux_kernel"),
    "media":          ("linux", "linux_kernel"),
    "jffs2":          ("linux", "linux_kernel"),
    "vold":           ("linux", "linux_kernel"),
    "init_rc":        ("linux", "linux_kernel"),
    "crypto":         ("linux", "linux_kernel"),
    "dm_verity_hash": ("linux", "linux_kernel"),
    "mmc":            ("linux", "linux_kernel"),
    "mtd":            ("linux", "linux_kernel"),
    "bionic":         ("linux", "linux_kernel"),
    "squashfs":       ("phillip_lougher", "squashfs"),
    "fuse_exfat":     ("dquinton",        "fuse-exfat"),
    "fuse_exfat2":    ("tuxera",          "exfat"),
}

KERNEL_SUBSYSTEM_KEYWORDS = {
    "dm_crypt": [
        r"\bdm[-_]crypt\b", r"\bdevice.mapper.crypt\b",
        r"\bcryptd\b", r"\bdrivers/md/dm-crypt\b",
    ],
    "dm_verity": [
        r"\bdm[-_]verity\b", r"\bdevice.mapper.verity\b",
        r"\bdrivers/md/dm-verity\b",
    ],
    "fs_mgr": [
        r"\bfs_mgr\b", r"\bfstab\b", r"\bfilesystem.manager\b",
        r"\bfs/fs_mgr\b",
    ],
    "media": [
        r"\bv4l2\b", r"\bvideo4linux\b", r"\bdvb\b",
        r"\bmedia.subsystem\b", r"\bdrivers/media\b",
        r"\bmedia/v4l2\b", r"\bvideobuf\b",
    ],
    "squashfs": [
        r"\bsquashfs\b", r"\bsqfs\b", r"\bfs/squashfs\b",
    ],
    "exfat": [
        r"\bexfat\b", r"\bfs/exfat\b",
    ],
    "jffs2": [
        r"\bjffs2\b",
        r"\bfs/jffs2\b",
        r"\bjournalling flash\b",
        r"\bjffs2_gc\b",
        r"\bjffs2_write\b",
        r"\bjffs2_summary\b",
        r"\bjffs2_compress\b",
    ],
    "vold": [
        r"\bvold\b",
        r"\bvolume.daemon\b",
        r"\bsystem/vold\b",
        r"\bvold_cryptfs\b",
        r"\bvold_prepare_subdirs\b",
        r"\bNetlinkManager\b",
        r"\bVolumeManager\b",
    ],
    "init_rc": [
        r"\binit\.rc\b",
        r"\binit\.[a-z0-9_]+\.rc\b",
        r"\bAndroid\.init\b",
        r"\bsystem/core/init\b",
        r"\bproperty_service\b",
        r"\bselinux.*?init\b",
        r"\binit.*?selinux\b",
        r"\bueventd\b",
        r"\bwatchdogd\b",
    ],
    "crypto": [
        r"\bcrypto.api\b",
        r"\bcrypto/\b",
        r"\blinux.crypto\b",
        r"\bcrypto.subsystem\b",
        r"\baes[-_]ce\b",
        r"\baes[-_]arm\b",
        r"\bsha256[-_]arm\b",
        r"\bsha512[-_]arm\b",
        r"\bghash[-_]ce\b",
        r"\bchacha20\b",
        r"\bpoly1305\b",
        r"\bskcipher\b",
        r"\baead\b",
        r"\bkpp\b",
        r"\bcrypto_engine\b",
        r"\bcaam\b",
        r"\bsafexcel\b",
        r"\bqce\b",
        r"\bce[-_]driver\b",
    ],
    "dm_verity_hash": [
        r"\bdm[-_]verity.*?hash\b",
        r"\bhash.*?dm[-_]verity\b",
        r"\broot.hash\b",
        r"\bverity.*?sha1\b",
        r"\bsha1.*?verity\b",
        r"\bunauthenticated.*?root.hash\b",
        r"\bfec\b",
        r"\bverity.*?bypass\b",
        r"\bhash.tree\b",
        r"\bverify_fec\b",
    ],
    "mmc": [
        r"\bmmc.subsystem\b",
        r"\bdrivers/mmc\b",
        r"\bmmcblk\b",
        r"\bemmc\b",
        r"\bmmc_send_cmd\b",
        r"\bmmc_blk_issue_rq\b",
        r"\bsdhci\b",
        r"\bsdhci[-_]pltfm\b",
        r"\bsdio\b",
        r"\bmmc_ioc_cmd\b",
        r"\bmmc_test\b",
        r"\btmmc\b",
    ],
    "mtd": [
        r"\bmtd.subsystem\b",
        r"\bdrivers/mtd\b",
        r"\bnand.flash\b",
        r"\bnor.flash\b",
        r"\bmtd_read\b",
        r"\bmtd_write\b",
        r"\bmtdblock\b",
        r"\bnandwrite\b",
        r"\bnft\b",
        r"\bnftl\b",
        r"\bubi_io\b",
        r"\bubi_wl\b",
        r"\bubi_vtbl\b",
        r"\bubivol\b",
        r"\bubi_scan\b",
        r"\bspi.?nor\b",
        r"\bm25p80\b",
        r"\bcfi_flash\b",
    ],
    "bionic": [
        r"\bbionic\b",
        r"\bbionic.libc\b",
        r"\bandroid.*?libc\b",
        r"\blibc\.so\b",
        r"\bglibc\b",
        r"\bgnu.c.library\b",
        r"\blibc[-_]dev\b",
        r"\bmusl\b",
        r"\bnewlib\b",
        r"\buClibc\b",
        r"\bsprintf.*?overflow\b",
        r"\bstrcpy.*?overflow\b",
        r"\bgets.*?overflow\b",
        r"\bformat.string.*?libc\b",
        r"\bpthread\b",
        r"\bfutex\b",
        r"\bdlopen\b",
        r"\bld[-_]linux\b",
        r"\blinker.*?android\b",
        r"\bandroid.*?linker\b",
    ],
}

BOOTLOADER_KEYWORDS = {
    "u-boot":   ["u-boot", "das u-boot", "uboot", "u_boot"],
    "grub":     ["grub2", "gnu grub", "grub version"],
    "barebox":  ["barebox"],
    "efi":      ["uefi", "edk2", "tianocore"],
    "coreboot": ["coreboot"],
    "lk":       ["little kernel", "lk bootloader"],
    "syslinux": ["syslinux", "isolinux"],
}

CRYPTO_ALGO_KEYWORDS = {
    "SHA256":    [r"\bsha256\b", r"\bsha-256\b"],
    "SHA1":      [r"\bsha1\b", r"\bsha-1\b"],
    "MD5":       [r"\bmd5\b"],
    "RSA":       [r"\brsa\b", r"\brsa1024\b", r"\brsa2048\b", r"\brsa4096\b"],
    "ECDSA":     [r"\becdsa\b"],
    "AES":       [r"\baes\b", r"\baes-128\b", r"\baes-256\b", r"\badvanced encryption standard\b"],
    "DES":       [r"\bdes\b", r"\b3des\b"],
    "ChaCha20":  [r"\bchacha20\b"],
    "Poly1305":  [r"\bpoly1305\b"]
}

FILE_FORMAT_KEYWORDS = {
    "FIT":       [r"\bfit\b", r"\bflattened image tree\b"],
    "uImage":    [r"\buimage\b"],
    "zImage":    [r"\bzimage\b"],
    "bzImage":   [r"\bbzimage\b"],
    "DTB":       [r"\bdtb\b", r"\bdevice tree blob\b", r"\bfdt\b", r"\bflattened device tree\b"],
    "initramfs": [r"\binitramfs\b", r"\binitrd\b", r"\bramdisk\b"],
    "cpio":      [r"\bcpio\b"]
}

FILESYSTEM_KEYWORDS = {
    "FAT":       [r"\bfat\b", r"\bfat16\b", r"\bfat32\b", r"\bvfat\b",
                  r"\bfatfs\b", r"\bfat filesystem\b"],
    "EXT4":      [r"\bext4\b", r"\bext4fs\b", r"\bfs/ext4\b"],
    "EXT2":      [r"\bext2\b", r"\bext2fs\b"],
    "BTRFS":     [r"\bbtrfs\b", r"\bfs/btrfs\b"],
    "F2FS":      [r"\bf2fs\b", r"\bfs/f2fs\b"],
    "OVERLAYFS": [r"\boverlayfs\b", r"\boverlay filesystem\b", r"\bfs/overlayfs\b"],
    "XFS":       [r"\bxfs\b", r"\bfs/xfs\b"],
    "NFS":       [r"\bnfsroot\b", r"\broot=nfs\b", r"\bnfs client\b",
                  r"\bnfs server\b", r"\bnfsd\b", r"\bnfs\b", r"\bnet/nfs\b"],
    "TMPFS":     [r"\btmpfs\b"],
    "JFFS2":     [r"\bjffs2\b", r"\bfs/jffs2\b", r"\bjournalling flash\b"],
    "SQUASHFS":  [r"\bsquashfs\b", r"\bsqfs\b", r"\bfs/squashfs\b"],
    "EROFS":     [r"\berofs\b", r"\bfs/erofs\b"],
    "UBIFS":     [r"\bubifs\b"],
    "UBI":       [r"\bubi\b", r"\bubifs\b"],
    "NAND":      [r"\bnand\b", r"\bnand flash\b"],
    "SPI_FLASH": [r"\bspi.?flash\b", r"\bnor flash\b", r"\bspi nor\b"],
    "TFTP":      [r"\btftp\b"],
    "MMC":       [r"\bmmc\b", r"\bemmc\b", r"\bsd.?card\b"],
    "CRAMFS":    [r"\bcramfs\b"],
    "YAFFS2":    [r"\byaffs2?\b"],
    "ROMFS":     [r"\bromfs\b"],
}

VENDOR_SIGNATURES = {
    "realtek": {
        "identifiers": [re.compile(r"\b(rts39[0-9]{2}|realtek|rts-)\b", re.I)],
        "custom_drivers": [
            (re.compile(r"usbphy-platform.*?:.*?Initialized.*?(usb\s*phy)", re.I), "usb_phy")
        ],
        "custom_failures": [
            (re.compile(r"rts-crypto.*?lookup\s+([a-zA-Z0-9_\-\(\)]+)\s*failed", re.I), "rts-crypto")
        ]
    },
    "broadcom": {
        "identifiers": [re.compile(r"\b(bcm|broadcom)\b", re.I)],
        "custom_drivers": [],
        "custom_failures": []
    },
    "mediatek": {
        "identifiers": [re.compile(r"\b(mtk|mediatek|mt[0-9]{4})\b", re.I)],
        "custom_drivers": [],
        "custom_failures": []
    },
    "nxp": {
        "identifiers": [re.compile(r"\b(imx|freescale|nxp)\b", re.I)],
        "custom_drivers": [],
        "custom_failures": []
    },
    "qualcomm": {
        "identifiers": [re.compile(r"\b(qcom|qualcomm|snapdragon|msm)\b", re.I)],
        "custom_drivers": [],
        "custom_failures": []
    }
}


# =============================================================================
# SECTION 3: VERSION UTILITIES
# =============================================================================

def _normalize_version_string(version_str: str) -> str:
    v = version_str.strip()
    if v and v[0] in ("v", "V"):
        v = v[1:]
    if "+" in v:
        v = v.split("+")[0]
    v = re.sub(r"-\d+-g[0-9a-f]+(-dirty)?$", "", v)
    v = re.sub(r"-(?!rc\d)(?!beta)(?!alpha)[a-zA-Z]\w*$", "", v)
    return v


@lru_cache(maxsize=2048)
def _parse_version_tuple(version_str: str) -> tuple:
    v = _normalize_version_string(version_str)
    pre_release = None
    pre_match = re.search(r"-(rc|alpha|beta)(\d+)?$", v)
    if pre_match:
        pre_type = pre_match.group(1)
        pre_num = int(pre_match.group(2)) if pre_match.group(2) else 0
        pre_order = {"alpha": 0, "beta": 1, "rc": 2}
        pre_release = (pre_order.get(pre_type, 3), pre_num)
        v = v[:pre_match.start()]
    parts = []
    for segment in re.split(r"[.\-]", v):
        try:
            parts.append(int(segment))
        except ValueError:
            parts.append(0)
    parts.extend(pre_release if pre_release else (99, 0))
    return tuple(parts)


def compare_versions(v1: str, v2: str) -> int:
    if HAS_PACKAGING:
        try:
            pv1 = Version(_normalize_version_string(v1))
            pv2 = Version(_normalize_version_string(v2))
            return -1 if pv1 < pv2 else (1 if pv1 > pv2 else 0)
        except InvalidVersion:
            pass
    t1 = _parse_version_tuple(v1)
    t2 = _parse_version_tuple(v2)
    return -1 if t1 < t2 else (1 if t1 > t2 else 0)


def is_version_in_range(version: str, cpe_match: dict) -> bool:
    si = cpe_match.get("versionStartIncluding")
    se = cpe_match.get("versionStartExcluding")
    ei = cpe_match.get("versionEndIncluding")
    ee = cpe_match.get("versionEndExcluding")
    has_range = any(x is not None for x in [si, se, ei, ee])
    if not has_range:
        cpe_parts = cpe_match.get("criteria", "").split(":")
        if len(cpe_parts) >= 6:
            cv = cpe_parts[5]
            if cv in ("*", "-"):
                return True
            return compare_versions(version, cv) == 0
        return False
    if si is not None and compare_versions(version, si) < 0:  return False
    if se is not None and compare_versions(version, se) <= 0: return False
    if ei is not None and compare_versions(version, ei) > 0:  return False
    if ee is not None and compare_versions(version, ee) >= 0: return False
    return True


def _is_kernel_branch_mismatch(version: str, cpe_matches: list) -> bool:
    user_parts = version.split('.')
    if len(user_parts) < 2: return False
    try:
        user_branch = float(f"{user_parts[0]}.{user_parts[1]}")
    except ValueError:
        return False

    cpe_branches = set()
    for cpe in cpe_matches:
        for key in ["versionStartIncluding", "versionStartExcluding"]:
            v = cpe.get(key)
            if v:
                parts = v.split('.')
                if len(parts) >= 2:
                    try:
                        return False
                    except ValueError: pass

        for key in ["versionEndExcluding", "versionEndIncluding"]:
            v = cpe.get(key)
            if v:
                parts = v.split('.')
                if len(parts) >= 2:
                    try:
                        cpe_branches.add(float(f"{parts[0]}.{parts[1]}"))
                    except ValueError: pass

    if not cpe_branches:
        return False

    lowest_cpe_branch = min(cpe_branches)
    if user_branch < lowest_cpe_branch:
        return True

    return False


def extract_version_from_cpe(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[5] if len(parts) >= 6 else ""

def extract_vendor_product_from_cpe(criteria: str) -> tuple:
    parts = criteria.split(":")
    return (parts[3], parts[4]) if len(parts) >= 5 else ("", "")


def extract_target_hw_from_cpe(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[11] if len(parts) >= 12 else "*"


# =============================================================================
# SECTION 4: BOOTLOG PARSER
# =============================================================================

_RE_UBOOT_MAIN    = re.compile(r"^U-Boot\s+(20\d{2}\.\d{2})([-\w.+]*)?\s+\(", re.MULTILINE | re.IGNORECASE)
_RE_UBOOT_ANY     = re.compile(r"U-Boot\s+(?:SPL\s+|TPL\s+)?(20\d{2}\.\d{2})([-\w.+]*)?", re.IGNORECASE)
_RE_UBOOT_SPL     = re.compile(r"U-Boot\s+SPL\s+(20\d{2}\.\d{2})([-\w.+]*)?", re.IGNORECASE)

_RE_CPU   = re.compile(r"^CPU\s*:\s+(.+)$",   re.MULTILINE)
_RE_SOC   = re.compile(r"^SoC\s*:\s+(.+)$",   re.MULTILINE)
_RE_MODEL = re.compile(r"^Model\s*:\s+(.+)$",  re.MULTILINE)
_RE_BOARD = re.compile(r"^Board\s*:\s+(.+)$",  re.MULTILINE)

_RE_ENV_FS      = re.compile(r"Loading\s+Environment\s+from\s+(\S+)", re.IGNORECASE)
_RE_FSLOAD      = re.compile(
    r"(fat|ext[24]|sqfs|ubifs|ubi|nfs|tftp|jffs2|btrfs|f2fs|xfs|erofs|overlay|cramfs|yaffs2?|romfs)"
    r"(?:load|mount|fs)?\b",
    re.IGNORECASE
)
_RE_LOAD_GENERIC = re.compile(r"^\s*load\s+(mmc|usb|scsi|sata|nvme|virtio)\s+", re.MULTILINE | re.IGNORECASE)

_RE_ROOTFSTYPE  = re.compile(r"rootfstype=(\w+)", re.IGNORECASE)
_RE_ROOT_MTD    = re.compile(r"root=/dev/mtdblock", re.IGNORECASE)
_RE_ROOT_UBI    = re.compile(r"root=ubi[:/]", re.IGNORECASE)
_RE_BOOTARGS    = re.compile(r"^(?:setenv\s+)?bootargs[= ]+(.+)$", re.MULTILINE | re.IGNORECASE)
_RE_FS_KEYWORD  = re.compile(
    r"\b(squashfs|jffs2|ubifs|cramfs|yaffs2|romfs|ext4|ext2|btrfs|f2fs|xfs|erofs|overlayfs)\b",
    re.IGNORECASE
)
_RE_SQUASHFS_MSG = re.compile(r"squashfs", re.IGNORECASE)
_RE_JFFS2_MSG    = re.compile(r"jffs2",    re.IGNORECASE)
_RE_UBIFS_MSG    = re.compile(r"ubifs",    re.IGNORECASE)
_RE_CRAMFS_MSG   = re.compile(r"cramfs",   re.IGNORECASE)
_RE_YAFFS_MSG    = re.compile(r"yaffs2?",  re.IGNORECASE)
_RE_OVERLAYFS    = re.compile(r"overlayfs",re.IGNORECASE)

_HW_COMPONENT_LABELS = [
    "DRAM", "MMC", "Net", "NAND", "SATA", "PCIe", "PCI", "WDT",
    "SF", "USB", "I2C", "SPI", "Flash", "EEPROM", "RTC", "GPIO",
    "Video", "Display", "PMIC", "Thermal", "Crypto", "CAAM", "DMA", "Timer",
]
_SERIAL_IO_LABELS = ["In", "Out", "Err"]
_RE_COMPONENTS = re.compile(
    r"^(" + "|".join(_HW_COMPONENT_LABELS + _SERIAL_IO_LABELS) + r")\s*:\s+(.+)$",
    re.MULTILINE,
)
_RE_SF_DETECT = re.compile(r"SF:\s+Detected\s+(\S+)\s+with\s+page\s+size", re.IGNORECASE)

_SUBSYSTEM_RE_TABLE = [
    (re.compile(r"\b(bluetooth|hci\d|btusb)\b",                    re.I), "bluetooth"),
    (re.compile(r"\b(cfg80211|mac80211|wlan\d|ieee80211|802\.11)\b",re.I), "wifi"),
    (re.compile(r"\b(ALSA|sound|snd[-_])\b",                       re.I), "sound"),
    (re.compile(r"\bkvm\b",                                         re.I), "kvm"),
    (re.compile(r"\b(drm|gpu|\[drm\])\b",                          re.I), "drm"),
    (re.compile(r"\b(nf_tables|nftables|iptables|netfilter|conntrack)\b", re.I), "netfilter"),
    (re.compile(r"\b(ipv6|inet6)\b",                                re.I), "ipv6"),
    (re.compile(r"\b(httpd|lighttpd|nginx|uhttpd|boa|mini_httpd)\b",re.I), "http"),
    (re.compile(r"\b(iommu|smmu|dmar)\b",                          re.I), "iommu"),
    (re.compile(r"\b(mtd\d|mtdblock)\b",                            re.I), "mtd"),
    (re.compile(r"\b(ebpf|bpf)\b",                                  re.I), "ebpf"),
    (re.compile(r"\bio_uring\b",                                    re.I), "io_uring"),
]

_RE_OPENSBI  = re.compile(r"OpenSBI\s+v?([\d.]+)",          re.IGNORECASE)
_RE_ATF_BL31 = re.compile(r"BL31:\s+v?([\d.]+)",            re.IGNORECASE)
_RE_OPTEE    = re.compile(r"OP-TEE.*?:\s+v?([\d.]+)",       re.IGNORECASE)
_RE_GRUB     = re.compile(r"GNU\s+GRUB\s+version\s+(\S+)",  re.IGNORECASE)
_RE_BAREBOX  = re.compile(r"barebox\s+(20\d{2}\.\d{2})(\S*)?", re.IGNORECASE)

_FW_RE_TABLE = [
    ("opensbi",  _RE_OPENSBI,  1),
    ("atf_bl31", _RE_ATF_BL31, 1),
    ("optee",    _RE_OPTEE,    1),
    ("grub",     _RE_GRUB,     1),
    ("barebox",  _RE_BAREBOX,  2),
]

_RE_LINUX_VERSION  = re.compile(r"Linux version (\d+\.\d+[\d.]*[-\w]*)",  re.IGNORECASE)
_RE_LINUX_DATE     = re.compile(r"Linux version [^\n]+?(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+([A-Za-z]{3})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}.*?\s+(\d{4})", re.IGNORECASE)
_RE_LINUX_DATE_ALT = re.compile(r"Linux version [^\n]+?(\d{4})-(\d{2})-(\d{2})")
_RE_SQUASHFS_VER   = re.compile(r"squashfs.*?version\s+([\d.]+)",          re.IGNORECASE)
_RE_FUSE_EXFAT_VER = re.compile(r"fuse[-_]exfat[^\d]*([\d.]+)",           re.IGNORECASE)
_RE_EXFAT_VER      = re.compile(r"\bexfat[^\d]*([\d.]+)",                  re.IGNORECASE)
_RE_GCC_VERSION    = re.compile(r"gcc version (\d+\.\d+(?:\.\d+)?)",       re.IGNORECASE)
_RE_TFA_VERSION    = re.compile(r"\b(?:TF-A|Trusted Firmware-A|ATF|BL[123]1?)\b[^\n\d]*?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_RE_BUSYBOX_VER    = re.compile(r"\bbusybox\b[^\d\n]*?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_RE_BUSYBOX_BEHAV  = re.compile(r"busybox.*?uninitialized urandom",        re.IGNORECASE)
_RE_OPENSSL_VER    = re.compile(r"\bOpenSSL[^\d\n]*?(\d+\.\d+(?:\.\d+[a-z]?)?)", re.IGNORECASE)
_RE_MBEDTLS_VER    = re.compile(r"(?:mbed\s*TLS|mbedtls|ARM\s*mbed\s*TLS)[^\d\n]*?v?(\d+\.\d+(?:\.\d+[a-z]?)?)", re.IGNORECASE)
_RE_MBEDTLS_BEHAV  = re.compile(r"Using crypto library ['\"]?(?:mbed\s*TLS|mbedtls)", re.IGNORECASE)

_RE_FEATURE_FAIL = re.compile(
    r"\]\s*([a-zA-Z0-9_\-]+).*?:\s*(?:lookup|init|probe|loading|mount).*?\b([a-zA-Z0-9_\-\(\)]+)\s*(?:failed|disabled)\b",
    re.IGNORECASE
)
_SMART_DRIVER_EXTRACTORS = [
    re.compile(r"([a-zA-Z0-9_\-]+)(?:[\s0-9a-fA-F\-\.:]+)?:\s*.*?\b(?:probe|probed)\b", re.IGNORECASE),
    re.compile(r"\]\s*([a-zA-Z0-9_\-]+)\s*(?:[0-9a-fA-F-]+)?:\s*(?:.*\bprobe\b|.*\bprobed\b)", re.IGNORECASE),
    re.compile(r"\b(?:found|registered|detected|attached)\s+([a-zA-Z0-9_\-]+)", re.IGNORECASE),
    re.compile(r"\]\s*([a-zA-Z0-9_\-]+).*?\s+driver\s+(?:registered|initialized|added)", re.IGNORECASE),
    re.compile(r"\]\s*([a-zA-Z0-9_\-]+).*?:\s*.*\binitialized\b", re.IGNORECASE)
]

_RE_VOLD = re.compile(
    r"\bvold\b|\bVolumeManager\b|\bNetlinkManager\b"
    r"|\bvold_prepare_subdirs\b|\bvold_cryptfs\b",
    re.IGNORECASE
)
_RE_INIT_RC = re.compile(
    r"\binit\.rc\b|\binit\.[a-z0-9_]+\.rc\b|\bproperty_service\b"
    r"|\bueventd\b|\bwatchdogd\b|\bsystem/core/init\b",
    re.IGNORECASE
)
_RE_CRYPTO = re.compile(
    r"\bcrypto.*?registered\b|\baes[-_]ce\b|\baes[-_]arm\b"
    r"|\bsha256[-_]arm\b|\bghash[-_]ce\b|\bchacha20\b|\bpoly1305\b"
    r"|\bcrypto_engine\b|\bcaam\b|\bqce\b",
    re.IGNORECASE
)
_RE_DM_VERITY_HASH = re.compile(
    r"\broot.hash\b|\bhash.tree\b|\bverity.*?sha1\b|\bfec\b|\bverify_fec\b",
    re.I
)
_RE_MMC = re.compile(
    r"\bmmcblk\d\b|\bsdhci\b|\bsdio\b|\bmmc\d+:.*?chip\b"
    r"|\bemmc.*?boot\b|\bmmc_send_cmd\b|\bmmc_ioc_cmd\b",
    re.IGNORECASE
)
_RE_MTD = re.compile(
    r"\bmtd\d\b|\bubi\d\b|\bnandwrite\b|\bnftl\b"
    r"|\bubi_scan\b|\bubi_io\b|\bspi.?nor\b|\bm25p80\b|\bcfi_flash\b",
    re.IGNORECASE
)
_RE_BIONIC = re.compile(
    r"\bbionic\b|\bglibc\b|\blibc\.so\b|\bld[-_]linux\b"
    r"|\bdl_open\b|\bpthread.*?init\b|\buClibc\b|\bmusl\b",
    re.IGNORECASE
)

_FS_CANONICAL = {
    "squashfs": "SQUASHFS", "jffs2": "JFFS2",  "ubifs": "UBIFS",
    "cramfs":   "CRAMFS",   "yaffs2":"YAFFS2",  "yaffs": "YAFFS2",
    "romfs":    "ROMFS",    "ext4":  "EXT4",    "ext2":  "EXT2",
    "btrfs":    "BTRFS",    "f2fs":  "F2FS",    "xfs":   "XFS",
    "erofs":    "EROFS",    "overlayfs":"OVERLAYFS",
}


def _unique_append(lst: list, val: str) -> None:
    if val not in lst:
        lst.append(val)


def _extract_cpu_keywords(cpu_line: str, model_line: str = "") -> set:
    keywords = set()
    combined = f"{cpu_line} {model_line}".lower()
    skip = {"rev", "running", "at", "mhz", "ghz", "rev1", "rev2",
            "the", "and", "for", "with", "rev1.0", "rev1.1", "rev2.0",
            "rev2.1", "evaluation", "board", "evk", "development", "kit"}
    for tok in re.findall(r"[a-z][a-z0-9._-]+", combined):
        if tok not in skip:
            keywords.add(tok)
    for m in re.findall(r"[A-Za-z]+[\d]+[A-Za-z\d]*", f"{cpu_line} {model_line}"):
        keywords.add(m.lower())
    return keywords


def _classify_architecture(cpu_keywords: set) -> str:
    for kw in cpu_keywords:
        kl = kw.lower()
        if kl in _ARCH_KEYWORD_MAP:
            return _ARCH_KEYWORD_MAP[kl]
        for arch_kw, arch_family in _ARCH_KEYWORD_MAP.items():
            if kl.startswith(arch_kw) or arch_kw.startswith(kl):
                return arch_family
    return "unknown"


def parse_bootlog(filepath: str) -> BootlogInfo:
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    info = BootlogInfo(raw_log=content)

    # 0. Heuristic Secrets Engine
    _RE_SECRETS = [
        re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*([a-zA-Z0-9!@#$%^&*_+-]{4,})"),
        re.compile(r"(?i)root\s*[:=]\s*([a-zA-Z0-9!@#$%^&*_+-]{4,})"),
        re.compile(r"(?i)login\s*[:=]\s*([a-zA-Z0-9!@#$%^&*_+-]{4,})"),
    ]
    for regex in _RE_SECRETS:
        for m in regex.finditer(content):
            secret = m.group(1).strip()
            if secret.lower() not in ("root", "admin", "admin123", "password", "none", "null", "true", "false", "yes", "no"):
                if secret not in info.leaked_secrets:
                    info.leaked_secrets.append(secret)

    main_m = _RE_UBOOT_MAIN.search(content)
    if main_m:
        info.bootloader_version    = main_m.group(1)
        info.bootloader_suffix     = main_m.group(2) or ""
        ls = content.rfind("\n", 0, main_m.start()) + 1
        le = content.find("\n", main_m.end())
        info.bootloader_full_string = content[ls:(le if le != -1 else len(content))].strip()
    else:
        for m in _RE_UBOOT_ANY.finditer(content):
            if not info.bootloader_version:
                info.bootloader_version = m.group(1)
                info.bootloader_suffix  = m.group(2) or ""
                ls = content.rfind("\n", 0, m.start()) + 1
                le = content.find("\n", m.end())
                info.bootloader_full_string = content[ls:(le if le != -1 else len(content))].strip()

    spl_seen: list = []
    for m in _RE_UBOOT_SPL.finditer(content):
        _unique_append(spl_seen, m.group(1) + (m.group(2) or ""))
    if spl_seen:
        info.spl_version = spl_seen[0]

    cpu_parts: list = []
    for m in _RE_CPU.finditer(content):
        _unique_append(cpu_parts, m.group(1).strip())
    for m in _RE_SOC.finditer(content):
        _unique_append(cpu_parts, m.group(1).strip())
    info.cpu_raw = " | ".join(cpu_parts)

    model_parts: list = []
    for m in _RE_MODEL.finditer(content):
        _unique_append(model_parts, m.group(1).strip())
    for m in _RE_BOARD.finditer(content):
        _unique_append(model_parts, m.group(1).strip())
    info.model_raw = " | ".join(model_parts)

    info.cpu_keywords     = _extract_cpu_keywords(info.cpu_raw, info.model_raw)
    info.cpu_architecture = _classify_architecture(info.cpu_keywords)

    _FS_ENV_MAP = {
        "SPIFLASH": "SPI_FLASH", "SPI": "SPI_FLASH",
        "FLASH":    "FLASH",     "NAND": "NAND",
    }
    for m in _RE_ENV_FS.finditer(content):
        fs = m.group(1).upper()
        info.filesystems.add(_FS_ENV_MAP.get(fs, fs))

    _FS_LOAD_MAP = {
        "EXT2": "EXT2",  "EXT4": "EXT4",  "FAT": "FAT",   "SQFS": "SQUASHFS",
        "UBIFS":"UBIFS", "UBI":  "UBI",   "NFS": "NFS",   "TFTP": "TFTP",
        "JFFS2":"JFFS2", "BTRFS":"BTRFS", "F2FS":"F2FS",  "XFS":  "XFS",
        "EROFS":"EROFS", "OVERLAY":"OVERLAYFS",
        "CRAMFS":"CRAMFS", "YAFFS2":"YAFFS2", "YAFFS":"YAFFS2", "ROMFS":"ROMFS",
    }
    for m in _RE_FSLOAD.finditer(content):
        fs = m.group(1).upper()
        info.filesystems.add(_FS_LOAD_MAP.get(fs, fs))

    for m in _RE_LOAD_GENERIC.finditer(content):
        info.filesystems.add(f"BLOCK_{m.group(1).upper()}")

    for m in _RE_ROOTFSTYPE.finditer(content):
        canonical = _FS_CANONICAL.get(m.group(1).lower(), m.group(1).upper())
        info.filesystems.add(canonical)

    if _RE_ROOT_MTD.search(content):
        info.filesystems.add("MTD_BLOCK")

    if _RE_ROOT_UBI.search(content):
        info.filesystems.add("UBIFS")
        info.filesystems.add("UBI")

    _FS_KEYWORD_MAP = {
        (_RE_SQUASHFS_MSG, "SQUASHFS"),
        (_RE_JFFS2_MSG,    "JFFS2"),
        (_RE_UBIFS_MSG,    "UBIFS"),
        (_RE_CRAMFS_MSG,   "CRAMFS"),
        (_RE_YAFFS_MSG,    "YAFFS2"),
        (_RE_OVERLAYFS,    "OVERLAYFS"),
    }
    for regex, fs_name in _FS_KEYWORD_MAP:
        if regex.search(content):
            info.filesystems.add(fs_name)

    _FILE_FORMAT_MAP = [
        (re.compile(r"\bFIT\b|\bFlattened Image Tree\b", re.IGNORECASE), "FIT"),
        (re.compile(r"\buImage\b", re.IGNORECASE), "uImage"),
        (re.compile(r"\bzImage\b", re.IGNORECASE), "zImage"),
        (re.compile(r"\bbzImage\b", re.IGNORECASE), "bzImage"),
        (re.compile(r"\bDTB\b|\bdevice tree blob\b|\bfdt\b", re.IGNORECASE), "DTB"),
        (re.compile(r"\binitramfs\b|\binitrd\b|\bramdisk\b", re.IGNORECASE), "initramfs"),
        (re.compile(r"\bcpio\b", re.IGNORECASE), "cpio"),
    ]
    for regex, format_name in _FILE_FORMAT_MAP:
        if regex.search(content):
            info.file_formats.add(format_name)

    for fw_key, fw_re, num_groups in _FW_RE_TABLE:
        seen: list = []
        for m in fw_re.finditer(content):
            ver = m.group(1) + ((m.group(2) or "") if num_groups >= 2 else "")
            _unique_append(seen, ver)
        if seen:
            info.additional_firmware[fw_key] = seen[0]

    kv_seen: list = []
    for m in _RE_LINUX_VERSION.finditer(content):
        _unique_append(kv_seen, m.group(1))
    if kv_seen:
        info.kernel_version = kv_seen[0]

    _MONTHS = {"jan": "01", "feb": "02", "mar": "03", "apr": "04", "may": "05", "jun": "06",
               "jul": "07", "aug": "08", "sep": "09", "oct": "10", "nov": "11", "dec": "12"}
    d_m = _RE_LINUX_DATE.search(content)
    if d_m:
        month = _MONTHS.get(d_m.group(1).lower()[:3], "01")
        day = d_m.group(2).zfill(2)
        year = d_m.group(3)
        info.kernel_build_date = f"{year}-{month}-{day}"
    else:
        d_m2 = _RE_LINUX_DATE_ALT.search(content)
        if d_m2:
            info.kernel_build_date = f"{d_m2.group(1)}-{d_m2.group(2)}-{d_m2.group(3)}"

    sqfs_seen: list = []
    for m in _RE_SQUASHFS_VER.finditer(content):
        _unique_append(sqfs_seen, m.group(1))
    if sqfs_seen:
        info.squashfs_version = sqfs_seen[0]

    for regex in (_RE_FUSE_EXFAT_VER, _RE_EXFAT_VER):
        for m in regex.finditer(content):
            info.fuse_exfat_version = m.group(1)
            break
        if info.fuse_exfat_version:
            break

    gcc_seen: list = []
    for m in _RE_GCC_VERSION.finditer(content):
        _unique_append(gcc_seen, m.group(1))
    if gcc_seen:
        info.gcc_version = gcc_seen[0]

    tfa_seen: list = []
    for m in _RE_TFA_VERSION.finditer(content):
        _unique_append(tfa_seen, m.group(1))
    if tfa_seen:
        info.tfa_version = tfa_seen[0]
        info.kernel_subsystems.add(f"tf-a (v{info.tfa_version})")

    bb_seen: list = []
    for m in _RE_BUSYBOX_VER.finditer(content):
        _unique_append(bb_seen, m.group(1))
    if bb_seen:
        info.busybox_version = bb_seen[0]
    elif _RE_BUSYBOX_BEHAV.search(content):
        info.busybox_behavior = True

    ossl_seen: list = []
    for m in _RE_OPENSSL_VER.finditer(content):
        _unique_append(ossl_seen, m.group(1))
    if ossl_seen:
        info.openssl_version = ossl_seen[0]

    mbed_seen: list = []
    for m in _RE_MBEDTLS_VER.finditer(content):
        _unique_append(mbed_seen, m.group(1))
    if mbed_seen:
        info.mbedtls_version = mbed_seen[0]
    elif _RE_MBEDTLS_BEHAV.search(content):
        info.mbedtls_behavior = True

    for m in _RE_FEATURE_FAIL.finditer(content):
        driver = m.group(1).lower()
        feature_str = m.group(2).lower()
        features = [x for x in re.split(r'[^a-zA-Z0-9_]+', feature_str) if x]
        if driver not in info.failed_features:
            info.failed_features[driver] = set()
        info.failed_features[driver].update(features)

    _ENGLISH_STOPWORDS = {
        "this", "that", "the", "a", "an", "is", "was", "are", "were", "with", "protocol",
        "new", "advanced", "capacity", "devtmpfs", "otp", "and", "or", "for", "on", "in",
        "to", "of", "by", "from", "at", "it", "as", "be", "has", "have", "had", "not",
        "but", "what", "which", "who", "when", "where", "why", "how", "all", "any", "both",
        "each", "few", "more", "most", "other", "some", "such", "no", "nor", "too", "very",
        "can", "will", "just", "should", "now", "device", "driver", "system", "kernel",
        "module", "probing", "detecting", "found", "error", "failed", "success",
        "started", "stopped", "using", "used", "support", "supported", "unsupported",
        "detect", "detected", "register", "registered", "initialize", "initialized", "add",
        "added", "remove", "removed", "enable", "enabled", "disable", "disabled", "create",
        "created", "delete", "deleted", "open", "opened", "close", "closed", "read", "write",
        "memory", "cpu", "board", "model", "vendor", "version", "build", "date", "time",
        "file", "folder", "path", "line", "code", "data", "info", "warn", "warning", "err",
        "debug", "trace", "log", "message", "msg", "type", "size", "length", "width",
        "height", "block", "sector", "page", "chunk", "bytes", "bits", "baud", "rate",
        "speed", "fast", "slow", "high", "low", "max", "min", "limit", "value", "count",
        "number", "num", "idx", "index", "id", "name", "string", "str", "char", "int",
        "long", "float", "double", "bool", "boolean", "true", "false", "yes", "no", "on",
        "off", "up", "down", "left", "right", "top", "bottom", "front", "back", "start",
        "end", "first", "last", "next", "prev", "previous", "main", "sub", "super",
        "root", "admin", "user", "guest", "group", "owner", "mode", "perm", "permission",
        "access", "deny", "allow", "grant", "revoke", "lock", "unlock", "key", "password",
        "pass", "token", "auth", "login", "logout", "session", "connection", "connect",
        "disconnect", "send", "receive", "tx", "rx", "in", "out", "input", "output",
        "execute", "exec", "run", "stop", "halt", "reboot", "restart", "reset", "power",
        "sleep", "wake", "suspend", "resume", "idle", "active", "busy", "ready", "wait",
        "waiting", "timeout", "abort", "cancel", "fail", "pass", "ok", "good", "bad",
        "unknown", "valid", "invalid", "check", "test", "verify", "match", "mismatch",
        "compare", "equal", "diff", "different", "same", "similar", "change", "changed",
        "update", "updated", "upgrade", "upgraded", "install", "installed", "uninstall",
        "uninstalled", "load", "loaded", "unload", "unloaded", "mount", "mounted",
        "unmount", "unmounted", "format", "formatted", "clean", "cleaned", "clear",
        "cleared", "erase", "erased", "read-only", "read-write", "ro", "rw", "none",
        "null", "empty", "full", "half", "quarter", "zero", "one", "two", "three",
        "four", "five", "six", "seven", "eight", "nine", "ten", "hundred", "thousand",
        "million", "billion", "byte", "kilobyte", "megabyte", "gigabyte", "terabyte",
        "kb", "mb", "gb", "tb"
    }

    for extractor in _SMART_DRIVER_EXTRACTORS:
        for m in extractor.finditer(content):
            driver = m.group(1).lower()
            if len(driver) > 2 and driver not in _ENGLISH_STOPWORDS:
                info.initialized_drivers.add(driver)

    for vendor_name, vendor_rules in VENDOR_SIGNATURES.items():
        matched_vendor = False
        for identifier_re in vendor_rules.get("identifiers", []):
            if identifier_re.search(content):
                matched_vendor = True
                break

        if matched_vendor:
            info.detected_vendors.add(vendor_name)
            for driver_re, driver_name in vendor_rules.get("custom_drivers", []):
                for m in driver_re.finditer(content):
                    info.initialized_drivers.add(driver_name)
            for fail_re, subsystem in vendor_rules.get("custom_failures", []):
                for m in fail_re.finditer(content):
                    features = [x for x in re.split(r'[^a-zA-Z0-9_]+', m.group(1).lower()) if x]
                    if subsystem not in info.failed_features:
                        info.failed_features[subsystem] = set()
                    info.failed_features[subsystem].update(features)

    def _exclude(subsys, features):
        if subsys not in info.failed_features:
            info.failed_features[subsys] = set()
        info.failed_features[subsys].update(features)

    all_comps = info.filesystems

    if "USB" not in all_comps:
        _exclude("media", {"usb", "pvrusb2", "mceusb", "cx231xx", "uvcvideo", "em28xx", "dvb-usb", "tvp5150", "hdpvr"})
        _exclude("net", {"usbnet", "rndis", "cdc_ether", "asix", "smsc95xx"})
        _exclude("bootloader", {"usb", "dfu", "dwc3", "xhci"})

    if "WIFI" not in all_comps and "wifi" not in all_comps:
        _exclude("net", {"mac80211", "cfg80211", "ath9k", "ath10k", "brcmfmac", "iwlwifi", "rtlwifi"})

    if "BLUETOOTH" not in all_comps and "bluetooth" not in all_comps:
        _exclude("net", {"bluetooth", "bluez", "l2cap", "rfcomm", "bnep", "hci"})

    if "PCIe" not in all_comps and "PCI" not in all_comps:
        _exclude("net", {"e1000e", "ixgbe", "igb", "tg3"})
        _exclude("media", {"bttv", "cx88", "saa7134", "tw5864", "tw686x", "solo6x10", "dt3155", "saa7164", "meye", "zoran"})

    if "msm" not in info.model_raw.lower() and "qualcomm" not in info.model_raw.lower():
        _exclude("media", {"msm", "msm-camera", "cam_req_mgr", "cam_sync", "cam_isp"})

    if "rockchip" not in info.model_raw.lower() and "rk3" not in info.model_raw.lower():
        _exclude("media", {"rkisp1", "rockchip"})

    if "HDMI" not in all_comps and "hdmi" not in all_comps:
        _exclude("media", {"cec", "hdmi"})

    if "DVB" not in all_comps and "dvb" not in all_comps:
        _exclude("media", {"dvb", "dvb-core", "dvb-net", "dvb-frontends"})

    _exclude("media", {"vivid", "vim2m", "vimc", "visl"})

    if "Net" not in all_comps and "eth0" not in all_comps:
        _exclude("bootloader", {"tftp", "nfs", "bootp", "dhcp", "ping", "pxe", "netconsole", "udp"})

    if "UBIFS" not in info.filesystems and "NAND" not in all_comps:
        _exclude("mtd", {"ubi", "ubifs", "vtbl", "vtbl.c"})
        _exclude("fs", {"ubi", "ubifs"})

    _exclude("security", {"apparmor", "selinux", "smack", "tomoyo", "landlock"})
    _exclude("crypto", {"algif_hash", "af_alg", "algif_skcipher", "algif_aead"})

    if "tracing" not in all_comps and "ebpf" not in all_comps:
        _exclude("kernel-tracing", {"ftrace", "kprobes", "bpf", "perf", "tracepoints"})

    has_spi  = "SPI_FLASH" in all_comps
    has_nand = "NAND" in all_comps

    if has_spi and not has_nand:
        _exclude("mtd", {"nand", "rawnand", "inftl", "brcmnand", "atmel", "pmecc", "slc", "smc"})
    elif has_nand and not has_spi:
        _exclude("mtd", {"spi", "spi-nor", "qspi", "quadspi", "spiflash"})

    _KS_SCAN = [
        (re.compile(r"\bdm[-_]crypt\b",          re.I), "dm_crypt"),
        (re.compile(r"\bdm[-_]verity\b",          re.I), "dm_verity"),
        (re.compile(r"\bfs_mgr\b",                re.I), "fs_mgr"),
        (re.compile(r"\b(v4l2|dvb|video4linux)\b",re.I), "media"),
        (re.compile(r"\b(squashfs|sqfs)\b",       re.I), "squashfs"),
        (re.compile(r"\bexfat\b",                 re.I), "exfat"),
        (re.compile(r"\bjffs2\b",                 re.I), "jffs2"),
        (_RE_VOLD,           "vold"),
        (_RE_INIT_RC,        "init_rc"),
        (_RE_CRYPTO,         "crypto"),
        (_RE_DM_VERITY_HASH, "dm_verity_hash"),
        (_RE_MMC,            "mmc"),
        (_RE_MTD,            "mtd"),
        (_RE_BIONIC,         "bionic"),
    ]
    for regex, name in _KS_SCAN:
        if regex.search(content):
            info.kernel_subsystems.add(name)

    # Dynamically extract any additional subsystems defined in the prefix map
    for kw, subsys in _SUBSYSTEM_PREFIX_MAP.items():
        if re.search(r"\b" + re.escape(kw) + r"\b", content, re.IGNORECASE):
            info.kernel_subsystems.add(subsys)

    _CRYPTO_MAP = [
        (re.compile(r"\bsha256\b", re.IGNORECASE), "SHA256"),
        (re.compile(r"\bsha1\b",   re.IGNORECASE), "SHA1"),
        (re.compile(r"\bmd5\b",    re.IGNORECASE), "MD5"),
        (re.compile(r"\brsa\d*\b", re.IGNORECASE), "RSA"),
        (re.compile(r"\becdsa\b",  re.IGNORECASE), "ECDSA"),
        (re.compile(r"\baes\b",    re.IGNORECASE), "AES"),
        (re.compile(r"\bchacha20\b",re.IGNORECASE),"ChaCha20"),
        (re.compile(r"\bpoly1305\b",re.IGNORECASE),"Poly1305"),
    ]
    for rx, name in _CRYPTO_MAP:
        if rx.search(content):
            info.crypto_algos.add(name)

    return info


# =============================================================================
# SECTION 5: SHARED CVE HELPERS
# =============================================================================

def _stream_cve_database(cve_db_path: str, chunk_size: int = 10000):
    path = Path(cve_db_path)
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"CVE database directory not found: {path}")
    
    log.info(f"Crawling database directory in chunks of {chunk_size}...")
    chunk = []
    
    for root, _, files in os.walk(path):
        if "cves" not in root.replace(os.sep, "/"):
            continue
        for file in files:
            if file.startswith("CVE-") and file.endswith(".json"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            chunk.append(data)
                            if len(chunk) >= chunk_size:
                                yield chunk
                                chunk = []
                except Exception:
                    continue
                    
    if chunk:
        yield chunk

def _load_cve_database(cve_db_path: str) -> list:
    path = Path(cve_db_path)
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"CVE database directory not found: {path}")
    
    log.info("Crawling database directory (this may take a minute)...")
    entries = []
    
    for root, _, files in os.walk(path):
        # We only want to process files in cves/ year folders to avoid meta files
        if "cves" not in root.replace(os.sep, "/"):
            continue
        for file in files:
            if file.startswith("CVE-") and file.endswith(".json"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            entries.append(data)
                except Exception:
                    continue
                    
    log.info(f"Loaded {len(entries)} CVE entries from {cve_db_path}")
    return entries


def _get_cve_obj(entry: dict) -> dict:
    return entry

def _sync_get_id(cve_obj: dict) -> str:
    return cve_obj.get("cveMetadata", {}).get("cveId", "")

def _sync_get_last_modified(cve_obj: dict) -> str:
    return cve_obj.get("cveMetadata", {}).get("dateUpdated", "")

def _sync_get_published(cve_obj: dict) -> str:
    meta = cve_obj.get("cveMetadata", {})
    return meta.get("datePublished") or meta.get("dateUpdated") or meta.get("dateReserved", "")

def _get_description(cve_obj: dict) -> str:
    cna = cve_obj.get("containers", {}).get("cna", {})
    for desc in cna.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""

def _get_severity_and_score(cve_obj: dict) -> tuple:
    cna = cve_obj.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics", [])
    for m in metrics:
        if "cvssV3_1" in m:
            return m["cvssV3_1"].get("baseSeverity", "UNKNOWN"), m["cvssV3_1"].get("baseScore", 0.0)
        elif "cvssV3_0" in m:
            return m["cvssV3_0"].get("baseSeverity", "UNKNOWN"), m["cvssV3_0"].get("baseScore", 0.0)
        elif "cvssV2_0" in m:
            score = m["cvssV2_0"].get("baseScore", 0.0)
            sev = "HIGH" if score >= 7.0 else ("MEDIUM" if score >= 4.0 else "LOW")
            return sev, score
    return "UNKNOWN", 0.0

def _get_references(cve_obj: dict) -> list:
    cna = cve_obj.get("containers", {}).get("cna", {})
    return [r.get("url", "") for r in cna.get("references", []) if r.get("url")]

def _get_weaknesses(cve_obj: dict) -> list:
    cna = cve_obj.get("containers", {}).get("cna", {})
    cwes = []
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            if "cweId" in desc:
                cwes.append(desc["cweId"])
    return cwes

def _extract_fallback_version(desc: str, keyword: str) -> str:
    m = re.search(r'\b' + keyword + r'\s+([0-9a-z.-]+)', desc, re.IGNORECASE)
    return m.group(1) if m else None

def _get_cpe_matches(cve_obj: dict) -> list:
    results = []
    cna = cve_obj.get("containers", {}).get("cna", {})
    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "")
        product = affected.get("product", "")
        if vendor.lower() == "n/a" or product.lower() == "n/a":
            continue
        # Create a mock criteria string compatible with the script's parsers
        criteria = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:*:*:*:*:*:*:*:*"
        for v in affected.get("versions", []):
            vuln = v.get("status", "affected") == "affected"
            v_start = v.get("version")
            if v_start in ("unspecified", "0", "*"):
                v_start = None
            results.append({
                "vulnerable": vuln,
                "criteria": criteria,
                "vendor": vendor.lower(),
                "product": product.lower(),
                "target_hw": "*",
                "versionStartIncluding": v_start,
                "versionStartExcluding": None,
                "versionEndIncluding": v.get("lessThanOrEqual"),
                "versionEndExcluding": v.get("lessThan"),
                "node_operator": "OR",
                "config_operator": "OR"
            })
            
    if not results:
        desc = _get_description(cve_obj).lower()
        fallback_map = {
            "u-boot": ("denx", "u-boot"),
            "squashfs": ("phillip_lougher", "squashfs"),
            "exfat": ("tuxera", "exfat"),
            "gcc": ("gnu", "gcc"),
            "trusted firmware-a": ("arm", "arm_trusted_firmware"),
            "arm trusted firmware": ("arm", "arm_trusted_firmware"),
            "busybox": ("busybox", "busybox"),
            "openssl": ("openssl", "openssl"),
            "mbed tls": ("arm", "mbedtls")
        }
        for kw, (f_vendor, f_product) in fallback_map.items():
            if kw in desc:
                results.append({
                    "vulnerable": True,
                    "criteria": f"cpe:2.3:a:{f_vendor}:{f_product}:*:*:*:*:*:*:*:*",
                    "vendor": f_vendor,
                    "product": f_product,
                    "target_hw": "*",
                    "versionStartIncluding": None,
                    "versionStartExcluding": None,
                    "versionEndIncluding": _extract_fallback_version(desc, "through"),
                    "versionEndExcluding": _extract_fallback_version(desc, "before"),
                    "node_operator": "OR",
                    "config_operator": "OR"
                })
    return results

def _format_version_range(cpe_match: dict) -> str:
    parts = []
    if cpe_match.get("versionStartIncluding"): parts.append(f">={cpe_match['versionStartIncluding']}")
    if cpe_match.get("versionStartExcluding"): parts.append(f">{cpe_match['versionStartExcluding']}")
    if cpe_match.get("versionEndIncluding"):   parts.append(f"<={cpe_match['versionEndIncluding']}")
    if cpe_match.get("versionEndExcluding"):   parts.append(f"<{cpe_match['versionEndExcluding']}")
    if parts:
        return ", ".join(parts)
    ver = extract_version_from_cpe(cpe_match.get("criteria", ""))
    return f"={ver}" if ver and ver != "*" else "all versions"


def _detect_arch_in_text(text: str) -> set:
    text_lower = text.lower()
    found = set()
    for family, keywords in ARCH_FAMILIES.items():
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                found.add(family)
                break
    return found


def _check_upstream_downstream_date(build_date_str: str, cve_published_str: str) -> dict:
    if not build_date_str or not cve_published_str:
        return {"Risk Level": "Unknown", "Justification": "Missing build or CVE date for comparison"}
    try:
        build_dt = datetime.strptime(build_date_str[:10], "%Y-%m-%d")
        cve_dt   = datetime.strptime(cve_published_str[:10], "%Y-%m-%d")
        if build_dt > cve_dt:
            return {"Risk Level": "Low / Likely Patched", "Justification": f"Device built ({build_date_str[:10]}) AFTER CVE published ({cve_published_str[:10]})"}
        else:
            return {"Risk Level": "High / Unpatched", "Justification": f"Device built ({build_date_str[:10]}) BEFORE OR ON CVE published ({cve_published_str[:10]})"}
    except ValueError:
        return {"Risk Level": "Unknown", "Justification": "Date format parsing error"}


def _check_cpu_compatibility(bootlog_info: BootlogInfo, cpe_matches: list, description: str) -> tuple:
    bootlog_arch = bootlog_info.cpu_architecture
    if not bootlog_arch or bootlog_arch == "unknown":
        return True, "no_cpu_in_bootlog", "Could not determine CPU architecture from bootlog"
    cpe_archs = set()
    for cpe in cpe_matches:
        hw = cpe.get("target_hw", "*")
        if hw and hw not in ("*", "-"):
            hw_lower = hw.lower()
            for family, keywords in ARCH_FAMILIES.items():
                if hw_lower in keywords or any(kw in hw_lower for kw in keywords):
                    cpe_archs.add(family)
                    break
    if cpe_archs:
        if bootlog_arch in cpe_archs:
            return True, "matched", f"CPE target_hw matches bootlog arch ({bootlog_arch})"
        return False, "cpu_mismatch_cpe", f"CPE target_hw {cpe_archs} != bootlog arch {bootlog_arch}"
    desc_archs = _detect_arch_in_text(description)
    if not desc_archs:
        return True, "no_cpu_in_cve", "No CPU/arch info in CPE or description — keeping for safety"
    if bootlog_arch in desc_archs:
        return True, "matched", f"Description mentions {bootlog_arch} which matches bootlog"
    return False, "cpu_mismatch_desc", f"Description mentions {desc_archs} but bootlog is {bootlog_arch}"


def _word_match(keyword: str, text: str) -> bool:
    return bool(re.search(r"\b" + re.escape(keyword) + r"\b", text, re.IGNORECASE))


def _check_bootloader_description(bootlog_info: BootlogInfo, description: str) -> tuple:
    desc_lower = description.lower()

    active_bootloaders = set()
    if bootlog_info.bootloader_version:
        bl_full = bootlog_info.bootloader_full_string.lower()
        for bl_name, keywords in BOOTLOADER_KEYWORDS.items():
            for kw in keywords:
                if kw in bl_full:
                    active_bootloaders.add(bl_name)
                    break

    for fw_key in bootlog_info.additional_firmware:
        if fw_key in BOOTLOADER_KEYWORDS:
            active_bootloaders.add(fw_key)

    if not active_bootloaders:
        active_bootloaders.add("u-boot")

    mentioned_bootloaders = set()
    for bl_name, keywords in BOOTLOADER_KEYWORDS.items():
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", desc_lower):
                mentioned_bootloaders.add(bl_name)
                break

    if not mentioned_bootloaders:
        return True, ""

    if active_bootloaders.intersection(mentioned_bootloaders):
        return True, ""

    others = mentioned_bootloaders - active_bootloaders
    if others:
        return False, f"CVE is about {others}, not the detected bootloaders {active_bootloaders}"
    return True, ""


# =============================================================================
# SECTION 6: SCAN 1 — BOOTLOADER / FIRMWARE CVEs
# =============================================================================

def scan_bootloader_cves(bootlog_info: BootlogInfo, entries: list, verbose: bool = False, print_stats: bool = True) -> list:
    target_products = set()
    if bootlog_info.bootloader_version:
        target_products.add(("denx", "u-boot"))

    for fw_key in bootlog_info.additional_firmware:
        if fw_key in KNOWN_PRODUCTS:
            target_products.add(KNOWN_PRODUCTS[fw_key])

    if not target_products:
        target_products.add(("denx", "u-boot"))

    matched_cves = []
    stats = {"total": len(entries), "pre_filtered": 0, "stage1": 0,
             "stage2": 0, "cpu_filtered": 0, "final": 0}

    for entry in entries:
        cve_obj = _get_cve_obj(entry)
        cve_id = _sync_get_id(cve_obj)
        cpe_matches = _get_cpe_matches(cve_obj)
        if not cpe_matches:
            continue

        relevant_cpes = []
        matched_product = matched_vendor = ""
        for cpe in cpe_matches:
            v, p = cpe.get("vendor", "").lower(), cpe.get("product", "").lower()
            for tv, tp in target_products:
                if v == tv and p == tp:
                    relevant_cpes.append(cpe)
                    matched_product, matched_vendor = tp, tv
                    break
        if not relevant_cpes:
            continue
        stats["pre_filtered"] += 1

        version_to_check = ""
        if matched_product == "u-boot":
            version_to_check = bootlog_info.bootloader_version
        elif matched_product in bootlog_info.additional_firmware:
            version_to_check = bootlog_info.additional_firmware[matched_product]
        else:
            for fw_key, (v, p) in KNOWN_PRODUCTS.items():
                if p == matched_product and v == matched_vendor:
                    version_to_check = bootlog_info.additional_firmware.get(fw_key, "")
                    break
        if not version_to_check:
            continue

        version_matched = False
        matching_cpe = None
        for cpe in relevant_cpes:
            if not cpe.get("vulnerable", True):
                continue
            if is_version_in_range(version_to_check, cpe):
                version_matched = True
                matching_cpe = cpe
                break
        if not version_matched:
            continue
        stats["stage1"] += 1

        description = _get_description(cve_obj)
        bl_relevant, bl_detail = _check_bootloader_description(bootlog_info, description)
        if not bl_relevant:
            if verbose:
                print(f"   [BOOTLOADER MISMATCH] {cve_id}: {bl_detail}")
            continue
        if matched_product in ("u-boot", "grub2", "barebox", "coreboot"):
            match_stage = "bootloader"
            component_matches = [f"Direct bootloader ({matched_product}) vulnerability"]
        else:
            match_stage = "firmware"
            component_matches = [f"Direct {matched_product} vulnerability"]
        stats["stage2"] += 1

        cpu_keep, cpu_reason, cpu_details = _check_cpu_compatibility(
            bootlog_info, cpe_matches, description)
        if not cpu_keep:
            stats["cpu_filtered"] += 1
            if verbose:
                print(f"   [CPU FILTERED] {cve_id}: {cpu_details}")
            continue

        severity, base_score = _get_severity_and_score(cve_obj)
        matched_cves.append(CVEMatch(
            cve_id=cve_id, description=description,
            severity=severity, base_score=base_score,
            published=_sync_get_published(cve_obj),
            last_modified=_sync_get_last_modified(cve_obj),
            matched_product=matched_product, matched_vendor=matched_vendor,
            matched_version_range=_format_version_range(matching_cpe) if matching_cpe else "",
            matched_components=component_matches, match_stage=match_stage,
            cpu_filter_result=cpu_reason, cpu_details=cpu_details,
            references=_get_references(cve_obj), weaknesses=_get_weaknesses(cve_obj),
            scan=1,
            date_risk=_check_upstream_downstream_date(
                bootlog_info.kernel_build_date,
                cve_obj.get("published", "")
            ),
        ))

    final_cves = []
    fp_count = 0
    for m in matched_cves:
        desc_lower = m.description.lower()

        for driver, failed_set in bootlog_info.failed_features.items():
            if driver != "bootloader" and driver != "all": continue
            for feat in failed_set:
                if len(feat) > 2 and re.search(r"\b" + re.escape(feat) + r"\b", desc_lower):
                    m.feature_proof = f"False Positive Proof: Requires '{feat}' which is hardware-disabled or missing in '{driver}'."
                    break
            if m.feature_proof: break

        desc_lower = m.description.lower()
        for fmt, patterns in FILE_FORMAT_KEYWORDS.items():
            if fmt not in bootlog_info.file_formats:
                for pat in patterns:
                    if re.search(pat, desc_lower):
                        m.feature_proof = f"False Positive (Missing File Format: {fmt})"
                        break
            if m.feature_proof: break

        for algo, patterns in CRYPTO_ALGO_KEYWORDS.items():
            if algo not in bootlog_info.crypto_algos:
                for pat in patterns:
                    if re.search(pat, desc_lower):
                        m.feature_proof = f"False Positive (Missing Crypto Algo: {algo})"
                        break
            if m.feature_proof: break

        if m.feature_proof and "False Positive" in m.feature_proof:
            fp_count += 1
            continue

        final_cves.append(m)

    matched_cves = final_cves
    stats["final"] = len(matched_cves)

    if print_stats:
        print(f"\n   [Scan 1] Statistics:")
        print(f"     Total CVEs scanned:         {stats['total']}")
        print(f"     Relevant product matches:   {stats['pre_filtered']}")
        print(f"     Version range matches:      {stats['stage1']}")
        print(f"     Component matches:          {stats['stage2']}")
        print(f"     CPU filtered out:           {stats['cpu_filtered']}")
        print(f"     Final vulnerabilities:      {stats['final']}")

    _sort_cves(matched_cves)
    return matched_cves


# =============================================================================
# SECTION 7: SCAN 2 — KERNEL VERSION + TOOL CVEs
# =============================================================================

# ---------------------------------------------------------------------------
# 7a. Commit-style subject prefix regex
# ---------------------------------------------------------------------------
_COMMIT_PREFIX_RE = re.compile(
    r"In the Linux kernel[^.]*?resolved\s*:\s*\n?\s*"
    r"([A-Za-z0-9_][A-Za-z0-9_\-/]*)[\s:,]",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# 7b. Commit-prefix → bootlog subsystem map
# ---------------------------------------------------------------------------
_SUBSYSTEM_PREFIX_MAP: dict = {
    "dm-crypt":       "dm_crypt",
    "dm-verity":      "dm_verity",
    "fs_mgr":         "fs_mgr",
    "android: fstab": "fs_mgr",
    "media":          "media",
    "v4l2":           "media",
    "dvb":            "media",
    "drivers/media":  "media",
    "squashfs":       "squashfs",
    "fs/squashfs":    "squashfs",
    "jffs2":          "jffs2",
    "fs/jffs2":       "jffs2",
    "yaffs":          "yaffs",
    "ext4":           "ext4",
    "f2fs":           "f2fs",
    "ubifs":          "ubifs",
    "exfat":          "exfat",
    "fuse-exfat":     "exfat",
    "crypto":         "crypto",
    "crypto_engine":  "crypto",
    "alg":            "crypto",
    "dm_crypt":       "crypto",
    "dm_verity":      "crypto",
    "caam":           "crypto",
    "qce":            "crypto",
    "inside-secure":  "crypto",
    "mmc":            "mmc",
    "mmc_core":       "mmc",
    "sdhci":          "mmc",
    "mmcblk":         "mmc",
    "sdio":           "mmc",
    "rtsmmc":         "mmc",
    "sdhci-msm":      "mmc",
    "sdhci-pltfm":    "mmc",
    "sdhci-esdhc":    "mmc",
    "sdhci-iproc":    "mmc",
    "mtd":            "mtd",
    "mtd_driver":     "mtd",
    "ubi":            "mtd",
    "spi-nor":        "mtd",
    "drivers/mtd":    "mtd",
    "drivers/ubi":    "mtd",
    "mtdblock":       "mtd",
    "spi-nand":       "mtd",
    "spic":           "mtd",
    "nand_ecc":       "mtd",
}

# ---------------------------------------------------------------------------
# 7c. Source-file path patterns
# ---------------------------------------------------------------------------
_SOURCE_PATH_MAP = [
    (re.compile(r"\bdrivers/md/dm-crypt\b",     re.I), "dm_crypt"),
    (re.compile(r"\bdrivers/md/dm-verity\b",    re.I), "dm_verity"),
    (re.compile(r"\bdrivers/media\b",           re.I), "media"),
    (re.compile(r"\bfs/squashfs\b",             re.I), "squashfs"),
    (re.compile(r"\bfs/jffs2\b",                re.I), "jffs2"),
    (re.compile(r"\bdrivers/mmc\b",             re.I), "mmc"),
    (re.compile(r"\bdrivers/mtd\b",             re.I), "mtd"),
    (re.compile(r"\bdrivers/ubi\b",             re.I), "mtd"),
    (re.compile(r"\bcrypto/[a-z0-9_\-]+\.c\b", re.I), "crypto"),
]

# ---------------------------------------------------------------------------
# 7d. First-sentence anchor patterns
# ---------------------------------------------------------------------------
_FIRST_SENTENCE_MAP = [
    (re.compile(r"\bjffs2",                                         re.I), "jffs2"),
    (re.compile(r"\bsquashfs",                                      re.I), "squashfs"),
    (re.compile(r"\bdm[-_]crypt\b",                                 re.I), "dm_crypt"),
    (re.compile(r"\bdm[-_]verity\b",                                re.I), "dm_verity"),
    (re.compile(r"\bv4l2\b|\bdvb[-_]core\b",                       re.I), "media"),
    (re.compile(r"\bmmcblk\b|\bsdhci\b|\bmmc_blk\b"
                r"|\bmmc_send_cmd\b|\bmmc_ioc_cmd\b",               re.I), "mmc"),
    (re.compile(r"\bnand.flash\b|\bubi_io\b|\bspi.nor\b"
                r"|\bnftl\b|\bubi_vtbl\b|\bubi_scan\b",             re.I), "mtd"),
    (re.compile(r"\bcrypto.api\b|\bskcipher\b|\baead\b"
                r"|\bcrypto_engine\b|\bkpp\b",                      re.I), "crypto"),
    (re.compile(r"\bvold\b|\bVolumeManager\b|\bNetlinkManager\b",   re.I), "vold"),
    (re.compile(r"\binit\.rc\b|\bproperty_service\b|\bueventd\b",   re.I), "init_rc"),
    (re.compile(r"\bbionic\b|\bglibc\b|\blibc\.so\b"
                r"|\bld[-_]linux\b|\bdlopen\b",                     re.I), "bionic"),
]

# ---------------------------------------------------------------------------
# 7e. Lore mailing-list URL → subsystem map
# ---------------------------------------------------------------------------
_LORE_LIST_MAP: dict = {
    "linux-mmc":    "mmc",
    "linux-mtd":    "mtd",
    "linux-media":  "media",
    "dm-devel":     "dm_crypt",
    "linux-crypto": "crypto",
}
_LORE_RE = re.compile(r"lore\.kernel\.org/([a-z0-9_\-]+)", re.I)


def _lookup_commit_prefix(raw_prefix: str):
    """Map a raw commit-subject prefix to a bootlog subsystem name, or None."""
    p = raw_prefix.lower().strip().rstrip(":/")
    for known, subsystem in _SUBSYSTEM_PREFIX_MAP.items():
        k = known.lower().rstrip(":/")
        if p == k:
            return subsystem
        if p.startswith(k + "/") or p.startswith(k + ":") or p.startswith(k + " "):
            return subsystem
    for known, subsystem in _SUBSYSTEM_PREFIX_MAP.items():
        k = known.lower().rstrip(":/")
        if p.startswith(k):
            return subsystem
    return None


def detect_kernel_subsystem(description: str, references: list):
    """
    Determine the Linux kernel subsystem affected by a CVE.
    Priority chain: commit-prefix → source-path → first-sentence → lore-URL.
    """
    commit_m = _COMMIT_PREFIX_RE.search(description)
    if commit_m:
        return _lookup_commit_prefix(commit_m.group(1))

    for path_re, subsystem in _SOURCE_PATH_MAP:
        if path_re.search(description):
            return subsystem

    first_sentence = re.split(r"[.!?\n]", description)[0] if description else ""
    for anchor_re, subsystem in _FIRST_SENTENCE_MAP:
        if anchor_re.search(first_sentence):
            return subsystem

    for url in references:
        lore_m = _LORE_RE.search(url)
        if lore_m:
            mapped = _LORE_LIST_MAP.get(lore_m.group(1).lower())
            if mapped:
                return mapped

    return None


def scan_kernel_cves(bootlog_info: BootlogInfo, entries: list, verbose: bool = False, print_stats: bool = True) -> list:
    matched_cves: list = []
    stats: dict = {
        "total":            len(entries),
        "kernel_found":     0,
        "squashfs_found":   0,
        "fuse_exfat_found": 0,
        "gcc_found":        0,
        "tfa_found":        0,
        "busybox_found":    0,
        "openssl_found":    0,
        "mbedtls_found":    0,
    }

    if bootlog_info.kernel_subsystems:
        active_subsystems: set = bootlog_info.kernel_subsystems
    else:
        active_subsystems = set(KERNEL_SUBSYSTEM_KEYWORDS.keys())

    kernel_target = ("linux", "linux_kernel")
    sqfs_targets  = {("phillip_lougher", "squashfs")}
    exfat_targets = {("dquinton", "fuse-exfat"), ("tuxera", "exfat")}

    seen_cve_ids: set = set()

    for entry in entries:
        cve_obj     = _get_cve_obj(entry)
        cve_id = _sync_get_id(cve_obj)
        cpe_matches = _get_cpe_matches(cve_obj)


        # ── Sub-scan A: Kernel subsystem CVEs ────────────────────────────────
        if bootlog_info.kernel_version and cve_id not in seen_cve_ids:
            kernel_cpes = [
                c for c in cpe_matches
                if c.get("vendor")  == kernel_target[0]
                and c.get("product") == kernel_target[1]
            ]
            if kernel_cpes:
                version_matched = any(
                    c.get("vulnerable", True)
                    and is_version_in_range(bootlog_info.kernel_version, c)
                    for c in kernel_cpes
                )

                if version_matched and _is_kernel_branch_mismatch(bootlog_info.kernel_version, kernel_cpes):
                    version_matched = False

                if version_matched:
                    description = _get_description(cve_obj)
                    references  = _get_references(cve_obj)

                    detected_subsystem = detect_kernel_subsystem(description, references)

                    if detected_subsystem is not None and detected_subsystem in active_subsystems:
                        cpu_keep, cpu_reason, cpu_details = _check_cpu_compatibility(
                            bootlog_info, cpe_matches, description)

                        if not cpu_keep:
                            if verbose:
                                print(f"   [CPU FILTERED] {cve_id}: {cpu_details}")
                            continue

                        seen_cve_ids.add(cve_id)

                        matching_cpe = next(
                            (c for c in kernel_cpes
                             if c.get("vulnerable", True)
                             and is_version_in_range(bootlog_info.kernel_version, c)),
                            None,
                        )
                        severity, base_score = _get_severity_and_score(cve_obj)
                        date_risk = _check_upstream_downstream_date(
                            bootlog_info.kernel_build_date,
                            cve_obj.get("published", "")
                        )
                        matched_cves.append(CVEMatch(
                            cve_id=cve_id,
                            description=description,
                            severity=severity,
                            base_score=base_score,
                            published=_sync_get_published(cve_obj),
                            last_modified=_sync_get_last_modified(cve_obj),
                            matched_product="linux_kernel",
                            matched_vendor="linux",
                            matched_version_range=_format_version_range(matching_cpe)
                                if matching_cpe else "",
                            matched_components=[
                                f"Kernel subsystem '{detected_subsystem}' "
                                f"detected via commit-prefix/source-path"
                            ],
                            match_stage="kernel_subsystem",
                            cpu_filter_result=cpu_reason,
                            cpu_details=cpu_details,
                            references=references,
                            weaknesses=_get_weaknesses(cve_obj),
                            scan=2,
                            subsystem=detected_subsystem,
                            date_risk=date_risk,
                        ))
                        stats["kernel_found"] += 1
                        if verbose:
                            print(f"   [KERNEL] {cve_id} ({detected_subsystem})")

        # ── Sub-scan B: Standalone SquashFS tool CVEs ─────────────────────────
        if bootlog_info.squashfs_version and cve_id not in seen_cve_ids:
            sqfs_cpes = [
                c for c in cpe_matches
                if (c.get("vendor"), c.get("product")) in sqfs_targets
                and c.get("vulnerable", True)
            ]
            if sqfs_cpes:
                seen_cve_ids.add(cve_id)
                matching_cpe = sqfs_cpes[0]
                description  = _get_description(cve_obj)
                severity, base_score = _get_severity_and_score(cve_obj)
                matched_cves.append(CVEMatch(
                    cve_id=cve_id,
                    description=description,
                    severity=severity,
                    base_score=base_score,
                    published=_sync_get_published(cve_obj),
                    last_modified=_sync_get_last_modified(cve_obj),
                    matched_product="squashfs",
                    matched_vendor="phillip_lougher",
                    matched_version_range=_format_version_range(matching_cpe),
                    matched_components=[
                        "SquashFS CVE — matched by product "
                        "(standalone tool version check skipped)"
                    ],
                    match_stage="tool",
                    cpu_filter_result="n/a",
                    cpu_details="SquashFS tool CVE — arch filter not applied",
                    references=_get_references(cve_obj),
                    weaknesses=_get_weaknesses(cve_obj),
                    scan=2,
                    subsystem="squashfs",
                    date_risk=_check_upstream_downstream_date(
                        bootlog_info.kernel_build_date,
                        cve_obj.get("published", "")
                    ),
                ))
                stats["squashfs_found"] += 1
                if verbose:
                    print(f"   [SQUASHFS] {cve_id}")

        # ── Sub-scan C: fuse-exfat CVEs ───────────────────────────────────────
        if bootlog_info.fuse_exfat_version and cve_id not in seen_cve_ids:
            exfat_cpes = [
                c for c in cpe_matches
                if "exfat" in c.get("product", "").lower()
            ]
            if exfat_cpes:
                version_matched = any(
                    c.get("vulnerable", True)
                    and is_version_in_range(bootlog_info.fuse_exfat_version, c)
                    for c in exfat_cpes
                )
                if version_matched:
                    seen_cve_ids.add(cve_id)
                    matching_cpe = next(
                        (c for c in exfat_cpes
                         if c.get("vulnerable", True)
                         and is_version_in_range(bootlog_info.fuse_exfat_version, c)),
                        None,
                    )
                    description  = _get_description(cve_obj)
                    severity, base_score = _get_severity_and_score(cve_obj)
                    matched_cves.append(CVEMatch(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        base_score=base_score,
                        published=_sync_get_published(cve_obj),
                        last_modified=_sync_get_last_modified(cve_obj),
                        matched_product="fuse-exfat",
                        matched_vendor=matching_cpe.get("vendor", "dquinton")
                            if matching_cpe else "dquinton",
                        matched_version_range=_format_version_range(matching_cpe)
                            if matching_cpe else "",
                        matched_components=[
                            f"fuse-exfat {bootlog_info.fuse_exfat_version} "
                            f"version range match"
                        ],
                        match_stage="tool",
                        cpu_filter_result="n/a",
                        cpu_details="fuse-exfat CVE — arch filter not applied",
                        references=_get_references(cve_obj),
                        weaknesses=_get_weaknesses(cve_obj),
                        scan=2,
                        subsystem="fuse_exfat",
                    ))
                    stats["fuse_exfat_found"] += 1
                    if verbose:
                        print(f"   [FUSE-EXFAT] {cve_id}")

        # ── Sub-scan D: GCC CVEs ──────────────────────────────────────────────
        if bootlog_info.gcc_version and cve_id not in seen_cve_ids:
            gcc_cpes = [
                c for c in cpe_matches
                if c.get("vendor") == "gnu" and c.get("product") == "gcc"
            ]
            if gcc_cpes:
                version_matched = any(
                    c.get("vulnerable", True)
                    and is_version_in_range(bootlog_info.gcc_version, c)
                    for c in gcc_cpes
                )
                if version_matched:
                    seen_cve_ids.add(cve_id)
                    matching_cpe = next(
                        (c for c in gcc_cpes
                         if c.get("vulnerable", True)
                         and is_version_in_range(bootlog_info.gcc_version, c)),
                        None,
                    )
                    description  = _get_description(cve_obj)
                    severity, base_score = _get_severity_and_score(cve_obj)
                    matched_cves.append(CVEMatch(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        base_score=base_score,
                        published=_sync_get_published(cve_obj),
                        last_modified=_sync_get_last_modified(cve_obj),
                        matched_product="gcc",
                        matched_vendor="gnu",
                        matched_version_range=_format_version_range(matching_cpe)
                            if matching_cpe else "",
                        matched_components=[
                            f"GCC Compiler "
                            f"(detected version: {bootlog_info.gcc_version})"
                        ],
                        match_stage="tool",
                        cpu_filter_result="n/a",
                        cpu_details="GCC CVE — arch filter not applied",
                        references=_get_references(cve_obj),
                        weaknesses=_get_weaknesses(cve_obj),
                        scan=2,
                        subsystem="gcc",
                    ))
                    stats["gcc_found"] += 1
                    if verbose:
                        print(f"   [GCC] {cve_id}")

        # ── Sub-scan E: TF-A CVEs ─────────────────────────────────────────────
        if bootlog_info.tfa_version and cve_id not in seen_cve_ids:
            tfa_cpes = [
                c for c in cpe_matches
                if c.get("product") in ("arm_trusted_firmware", "trusted_firmware-a", "arm-trusted-firmware")
            ]
            if tfa_cpes:
                version_matched = any(
                    c.get("vulnerable", True)
                    and is_version_in_range(bootlog_info.tfa_version, c)
                    for c in tfa_cpes
                )
                if version_matched:
                    seen_cve_ids.add(cve_id)
                    matching_cpe = next(
                        (c for c in tfa_cpes
                         if c.get("vulnerable", True)
                         and is_version_in_range(bootlog_info.tfa_version, c)),
                        None,
                    )
                    description  = _get_description(cve_obj)
                    severity, base_score = _get_severity_and_score(cve_obj)
                    matched_cves.append(CVEMatch(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        base_score=base_score,
                        published=_sync_get_published(cve_obj),
                        last_modified=_sync_get_last_modified(cve_obj),
                        matched_product=matching_cpe.get("product", "arm_trusted_firmware"),
                        matched_vendor=matching_cpe.get("vendor", "arm"),
                        matched_version_range=_format_version_range(matching_cpe)
                            if matching_cpe else "",
                        matched_components=[
                            f"Trusted Firmware-A (TF-A) "
                            f"(detected version: {bootlog_info.tfa_version})"
                        ],
                        match_stage="tool",
                        cpu_filter_result="n/a",
                        cpu_details="TF-A CVE — arch filter not applied",
                        references=_get_references(cve_obj),
                        weaknesses=_get_weaknesses(cve_obj),
                        scan=2,
                        subsystem="tf-a",
                    ))
                    stats["tfa_found"] += 1
                    if verbose:
                        print(f"   [TF-A] {cve_id}")

        # ── Sub-scan F: BusyBox CVEs ──────────────────────────────────────────
        if bootlog_info.busybox_version and cve_id not in seen_cve_ids:
            bb_cpes = [
                c for c in cpe_matches
                if "busybox" in c.get("product", "").lower()
            ]
            if bb_cpes:
                if bootlog_info.busybox_version:
                    version_matched = any(
                        c.get("vulnerable", True)
                        and is_version_in_range(bootlog_info.busybox_version, c)
                        for c in bb_cpes
                    )
                    bb_match_comp = f"BusyBox (detected version: {bootlog_info.busybox_version})"
                else:
                    date_risk_res = _check_upstream_downstream_date(
                        bootlog_info.kernel_build_date,
                        cve_obj.get("published", "")
                    )
                    if "Low" in date_risk_res.get("Risk Level", ""):
                        version_matched = False
                    else:
                        version_matched = any(c.get("vulnerable", True) for c in bb_cpes)
                    bb_match_comp = "BusyBox (detected via behavioral artifact: 'uninitialized urandom')"

                if version_matched:
                    seen_cve_ids.add(cve_id)
                    if bootlog_info.busybox_version:
                        matching_cpe = next((c for c in bb_cpes if c.get("vulnerable", True) and is_version_in_range(bootlog_info.busybox_version, c)), None)
                    else:
                        matching_cpe = next((c for c in bb_cpes if c.get("vulnerable", True)), None)

                    description  = _get_description(cve_obj)
                    severity, base_score = _get_severity_and_score(cve_obj)
                    matched_cves.append(CVEMatch(
                        cve_id=cve_id,
                        description=description,
                        severity=severity,
                        base_score=base_score,
                        published=_sync_get_published(cve_obj),
                        last_modified=_sync_get_last_modified(cve_obj),
                        matched_product="busybox",
                        matched_vendor=matching_cpe.get("vendor", "busybox") if matching_cpe else "busybox",
                        matched_version_range=_format_version_range(matching_cpe) if matching_cpe else "",
                        matched_components=[bb_match_comp],
                        match_stage="tool",
                        cpu_filter_result="n/a",
                        cpu_details="BusyBox CVE — arch filter not applied",
                        references=_get_references(cve_obj),
                        weaknesses=_get_weaknesses(cve_obj),
                        scan=2,
                        subsystem="busybox",
                        date_risk=_check_upstream_downstream_date(
                            bootlog_info.kernel_build_date,
                            cve_obj.get("published", "")
                        ),
                    ))
                    stats["busybox_found"] += 1
                    if verbose:
                        print(f"   [BUSYBOX] {cve_id}")

        # ── Sub-scan G: Crypto Libs (OpenSSL & mbed TLS) ─────────────────────
        if (bootlog_info.openssl_version or bootlog_info.mbedtls_version) and cve_id not in seen_cve_ids:

            if bootlog_info.openssl_version:
                ossl_cpes = [c for c in cpe_matches if "openssl" in c.get("product", "").lower()]
                if ossl_cpes:
                    version_matched = any(
                        c.get("vulnerable", True) and is_version_in_range(bootlog_info.openssl_version, c)
                        for c in ossl_cpes
                    )
                    if version_matched:
                        seen_cve_ids.add(cve_id)
                        matching_cpe = next((c for c in ossl_cpes if c.get("vulnerable", True) and is_version_in_range(bootlog_info.openssl_version, c)), None)
                        description  = _get_description(cve_obj)
                        severity, base_score = _get_severity_and_score(cve_obj)
                        matched_cves.append(CVEMatch(
                            cve_id=cve_id,
                            description=description,
                            severity=severity,
                            base_score=base_score,
                            published=_sync_get_published(cve_obj),
                            last_modified=_sync_get_last_modified(cve_obj),
                            matched_product="openssl",
                            matched_vendor="openssl",
                            matched_version_range=_format_version_range(matching_cpe) if matching_cpe else "",
                            matched_components=[f"OpenSSL (detected version: {bootlog_info.openssl_version})"],
                            match_stage="tool",
                            cpu_filter_result="n/a",
                            cpu_details="Crypto Lib CVE - arch filter not applied",
                            references=_get_references(cve_obj),
                            weaknesses=_get_weaknesses(cve_obj),
                            scan=2,
                            subsystem="openssl",
                            date_risk=_check_upstream_downstream_date(
                                bootlog_info.kernel_build_date,
                                cve_obj.get("published", "")
                            )
                        ))
                        stats["openssl_found"] += 1
                        if verbose:
                            print(f"   [OPENSSL] {cve_id}")

            if bootlog_info.mbedtls_version and cve_id not in seen_cve_ids:
                mbed_cpes = [
                    c for c in cpe_matches
                    if c.get("product") in ("mbed_tls", "mbedtls")
                ]
                if mbed_cpes:
                    if bootlog_info.mbedtls_version:
                        version_matched = any(
                            c.get("vulnerable", True) and is_version_in_range(bootlog_info.mbedtls_version, c)
                            for c in mbed_cpes
                        )
                        mbed_match_comp = f"mbed TLS (detected version: {bootlog_info.mbedtls_version})"
                    else:
                        date_risk_res = _check_upstream_downstream_date(
                            bootlog_info.kernel_build_date,
                            cve_obj.get("published", "")
                        )
                        if "Low" in date_risk_res.get("Risk Level", ""):
                            version_matched = False
                        else:
                            version_matched = any(c.get("vulnerable", True) for c in mbed_cpes)
                        mbed_match_comp = "mbed TLS (detected via behavioral artifact: 'Using crypto library')"

                    if version_matched:
                        seen_cve_ids.add(cve_id)
                        if bootlog_info.mbedtls_version:
                            matching_cpe = next((c for c in mbed_cpes if c.get("vulnerable", True) and is_version_in_range(bootlog_info.mbedtls_version, c)), None)
                        else:
                            matching_cpe = next((c for c in mbed_cpes if c.get("vulnerable", True)), None)

                        description  = _get_description(cve_obj)
                        severity, base_score = _get_severity_and_score(cve_obj)
                        matched_cves.append(CVEMatch(
                            cve_id=cve_id,
                            description=description,
                            severity=severity,
                            base_score=base_score,
                            published=_sync_get_published(cve_obj),
                            last_modified=_sync_get_last_modified(cve_obj),
                            matched_product="mbedtls",
                            matched_vendor="arm",
                            matched_version_range=_format_version_range(matching_cpe) if matching_cpe else "",
                            matched_components=[mbed_match_comp],
                            match_stage="tool",
                            cpu_filter_result="n/a",
                            cpu_details="Crypto Lib CVE - arch filter not applied",
                            references=_get_references(cve_obj),
                            weaknesses=_get_weaknesses(cve_obj),
                            scan=2,
                            subsystem="mbedtls",
                            date_risk=_check_upstream_downstream_date(
                                bootlog_info.kernel_build_date,
                                cve_obj.get("published", "")
                            )
                        ))
                        stats["mbedtls_found"] += 1
                        if verbose:
                            print(f"   [MBEDTLS] {cve_id}")

    # ── Post-Processing: Feature Proofs & False Positive Filtration ─────────
    final_cves = []
    fp_count = 0
    for m in matched_cves:
        desc_lower = m.description.lower()

        for driver, failed_set in bootlog_info.failed_features.items():
            if driver == "bootloader": continue
            for feat in failed_set:
                if len(feat) > 2 and re.search(r"\b" + re.escape(feat) + r"\b", desc_lower):
                    m.feature_proof = f"False Positive Proof: Requires '{feat}' which is hardware-disabled or failed in '{driver}'."
                    break
            if m.feature_proof: break

        desc_lower = m.description.lower()
        for fmt, patterns in FILE_FORMAT_KEYWORDS.items():
            if fmt not in bootlog_info.file_formats:
                for pat in patterns:
                    if re.search(pat, desc_lower):
                        m.feature_proof = f"False Positive (Missing File Format: {fmt})"
                        break
            if m.feature_proof: break

        for algo, patterns in CRYPTO_ALGO_KEYWORDS.items():
            if algo not in bootlog_info.crypto_algos:
                for pat in patterns:
                    if re.search(pat, desc_lower):
                        m.feature_proof = f"False Positive (Missing Crypto Algo: {algo})"
                        break
            if m.feature_proof: break

        if m.feature_proof and "False Positive" in m.feature_proof:
            fp_count += 1
            if m.subsystem == "mbedtls": stats["mbedtls_found"] -= 1
            elif m.subsystem == "squashfs": stats["squashfs_found"] -= 1
            elif m.subsystem == "fuse_exfat": stats["fuse_exfat_found"] -= 1
            elif m.subsystem == "gcc": stats["gcc_found"] -= 1
            elif m.subsystem == "tf-a": stats["tfa_found"] -= 1
            elif m.subsystem == "busybox": stats["busybox_found"] -= 1
            elif m.subsystem == "openssl": stats["openssl_found"] -= 1
            else: stats["kernel_found"] -= 1
            continue

        if not m.feature_proof:
            for driver in bootlog_info.initialized_drivers:
                if len(driver) > 3 and (re.search(r"\b" + re.escape(driver) + r"\b", desc_lower) or driver in m.matched_product):
                    m.feature_proof = f"True Positive Proof: Driver '{driver}' explicitly initialized."
                    break

        final_cves.append(m)

    if print_stats:
        print(f"\n   [Scan 2] Statistics:")
        print(f"     Kernel subsystem CVEs:      {stats['kernel_found']}")

        sub_counts = {}
        for m in final_cves:
            if m.subsystem and m.subsystem not in ("squashfs", "fuse_exfat"):
                sub_counts[m.subsystem] = sub_counts.get(m.subsystem, 0) + 1

        for sub, cnt in sorted(sub_counts.items()):
            print(f"       of which {sub:<18s} {cnt}")

        print(f"     SquashFS (tool) CVEs:       {stats['squashfs_found']}")
        print(f"     fuse-exfat CVEs:            {stats['fuse_exfat_found']}")
        print(f"     GCC Compiler CVEs:          {stats['gcc_found']}")
        print(f"     TF-A Firmware CVEs:         {stats['tfa_found']}")
        print(f"     BusyBox CVEs:               {stats['busybox_found']}")
        print(f"     OpenSSL CVEs:               {stats['openssl_found']}")
        print(f"     mbed TLS CVEs:              {stats['mbedtls_found']}")
        if fp_count > 0:
            print(f"     False Positives removed:    {fp_count}")
        print(f"     Total Scan 2 findings:      {len(final_cves)}")

    _sort_cves(final_cves)
    return final_cves


def _sort_cves(cves: list) -> None:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    cves.sort(key=lambda c: (order.get(c.severity, 5), -c.base_score))


# =============================================================================
# SECTION 8: REPORT GENERATOR
# =============================================================================

def _supports_color() -> bool:
    if os.getenv("NO_COLOR"):    return False
    if os.getenv("FORCE_COLOR"): return True
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            h   = k32.GetStdHandle(-11)
            m   = ctypes.c_ulong()
            k32.GetConsoleMode(h, ctypes.byref(m))
            k32.SetConsoleMode(h, m.value | 0x0004)
            return True
        except Exception:
            return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_USE_COLOR = _supports_color()

def _c(code, text): return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text
def _bold(t):    return _c("1", t)
def _red(t):     return _c("91", t)
def _yellow(t):  return _c("93", t)
def _green(t):   return _c("92", t)
def _cyan(t):    return _c("96", t)
def _dim(t):     return _c("2", t)
def _bg_red(t):  return _c("41;97", t)
def _magenta(t): return _c("95", t)

def _severity_color(severity, text=None):
    if text is None: text = severity
    sev = severity.upper()
    if sev == "CRITICAL": return _bg_red(f" {text} ")
    if sev == "HIGH":     return _red(text)
    if sev == "MEDIUM":   return _yellow(text)
    if sev == "LOW":      return _green(text)
    return _dim(text)

def _sep(width=80): print(_dim("─" * width))

_HIGHLIGHT_SUBSYSTEMS = {
    "jffs2", "vold", "init_rc", "crypto",
    "dm_verity_hash", "mmc", "mtd", "bionic",
}

def _print_cve_table(matches: list, width: int) -> None:
    print(_bold(f"  {'CVE ID':<18s} │ {'SEVERITY':<10s} │ {'SCORE'} │ {'PRODUCT':<15s} │ {'VERSIONS'}"))
    _sep(width)
    for m in matches:
        sev = _severity_color(m.severity, f"{m.severity:<10s}")
        print(f"  {_bold(m.cve_id):<18s} │ {sev} │ {m.base_score:>5.1f} │ {m.matched_product:<15s} │ {m.matched_version_range}")
    _sep(width)


def _print_cve_details(matches: list, width: int) -> None:
    import textwrap
    total = len(matches)
    for i, m in enumerate(matches, 1):
        scan_label = _cyan(f"[Scan {m.scan}]") if m.scan == 1 else _magenta(f"[Scan {m.scan}]")
        sub = f" / {m.subsystem}" if m.subsystem else ""
        print(_bold(_cyan(f"[{i}/{total}] {m.cve_id}")) + f"  {scan_label}{sub}")
        print(f"  {_bold('Severity:')}   {_severity_color(m.severity)} (Score: {m.base_score})")
        print(f"  {_bold('Product:')}    {m.matched_vendor}:{m.matched_product}")
        print(f"  {_bold('Versions:')}   {m.matched_version_range}")
        print(f"  {_bold('Published:')}  {m.published}")
        print(f"  {_bold('Updated:')}    {m.last_modified}")
        print(f"  {_bold('Stage:')}      {m.match_stage}")
        if m.cpu_filter_result and m.cpu_filter_result != "n/a":
            print(f"  {_bold('CPU Check:')}  {m.cpu_filter_result} -- {_dim(m.cpu_details)}")
        if m.date_risk:
            risk_level = m.date_risk.get("Risk Level", "Unknown")
            risk_just  = m.date_risk.get("Justification", "")
            color_func = _red if "High" in risk_level else (_green if "Low" in risk_level else _yellow)
            print(f"  {_bold('Date Risk:')}  {color_func(risk_level)} -- {_dim(risk_just)}")
        if m.weaknesses:
            print(f"  {_bold('CWE:')}        {', '.join(m.weaknesses)}")
        if m.feature_proof:
            proof_color = _yellow if "False Positive" in m.feature_proof else _green
            print(f"  {_bold('Proof:')}      {proof_color(m.feature_proof)}")
        if m.matched_components:
            print(f"  {_bold('Matches:')}")
            for c in m.matched_components:
                print(f"    - {c}")
        print(f"  {_bold('Description:')}")
        print(textwrap.fill(m.description, width=width-4, initial_indent="    ", subsequent_indent="    "))
        if m.references:
            seen = set()
            unique_refs = [r for r in m.references if not (r in seen or seen.add(r))]
            patches    = [r for r in unique_refs if "commit" in r.lower() or "patch" in r.lower() or "pull" in r.lower()]
            other_refs = [r for r in unique_refs if r not in patches]
            if patches:
                print(f"  {_bold('Patch Links:')}")
                for p in patches[:3]:
                    print(f"    -> {_green(p)}")
            if other_refs:
                print(f"  {_bold('References:')}")
                for r in other_refs[:3]:
                    print(f"    -> {_dim(r)}")
        _sep(width)


def generate_terminal_report(
    bootlog_info: BootlogInfo,
    scan1_matches: list,
    scan2_matches: list,
    verbose: bool = False,
):
    width = 80
    try:
        width = min(os.get_terminal_size().columns, 100)
    except Exception:
        pass

    print()
    print(_bold(_cyan("┏" + "━" * (width - 2) + "┓")))
    print(_bold(_cyan(f"┃{'BOOTLOG CVE VULNERABILITY SCANNER - DUAL STAGE':^{width-2}}┃")))
    print(_bold(_cyan("┗" + "━" * (width - 2) + "┛")))
    print()

    print(_bold(_cyan(" ─── EXTRACTED SYSTEM INFORMATION ───────────────────────────────────")))
    print(f"  {_bold('Bootloader:'):<18s} {bootlog_info.bootloader_full_string or 'Not detected'}")
    print(f"  {_bold('Version:'):<18s} {_cyan(bootlog_info.bootloader_version or 'N/A')}")
    if bootlog_info.spl_version:
        print(f"  {_bold('SPL Version:'):<18s} {bootlog_info.spl_version}")
    print(f"  {_bold('CPU/SoC:'):<18s} {bootlog_info.cpu_raw or 'Not detected'}")
    print(f"  {_bold('Architecture:'):<18s} {bootlog_info.cpu_architecture or 'Unknown'}")
    if bootlog_info.model_raw:
        print(f"  {_bold('Board Model:'):<18s} {bootlog_info.model_raw}")
    if bootlog_info.detected_vendors:
        print(f"  {_bold('Detected Vendor:'):<18s} {_magenta(', '.join(bootlog_info.detected_vendors))}")
    print(f"  {_bold('Filesystems:'):<18s} {', '.join(sorted(bootlog_info.filesystems)) or 'None'}")
    print(f"  {_bold('File Formats:'):<18s} {', '.join(sorted(bootlog_info.file_formats)) or 'None'}")
    print(f"  {_bold('Crypto Algos:'):<18s} {', '.join(sorted(bootlog_info.crypto_algos)) or 'None'}")
    if bootlog_info.additional_firmware:
        for fw, ver in bootlog_info.additional_firmware.items():
            print(f"  {_bold(fw.upper() + ':'):<18s} {ver}")
    if bootlog_info.kernel_version:
        print(f"  {_bold('Linux Kernel:'):<18s} {_cyan(bootlog_info.kernel_version)}")
    if bootlog_info.squashfs_version:
        print(f"  {_bold('SquashFS:'):<18s} {_cyan(bootlog_info.squashfs_version)}")
    if bootlog_info.fuse_exfat_version:
        print(f"  {_bold('fuse-exfat:'):<18s} {_cyan(bootlog_info.fuse_exfat_version)}")
    if bootlog_info.gcc_version:
        print(f"  {_bold('GCC:'):<18s} {_cyan(bootlog_info.gcc_version)}")
    if bootlog_info.tfa_version:
        print(f"  {_bold('TF-A:'):<18s} {_cyan(bootlog_info.tfa_version)}")
    if bootlog_info.busybox_version or bootlog_info.busybox_behavior:
        v = f"v{bootlog_info.busybox_version}" if bootlog_info.busybox_version else "(Behavioral Proof)"
        print(f"  {_bold('BusyBox:'):<18s} {_cyan(v)}")
    if bootlog_info.openssl_version:
        print(f"  {_bold('OpenSSL:'):<18s} {_cyan(f'v{bootlog_info.openssl_version}')}")
    if bootlog_info.mbedtls_version or bootlog_info.mbedtls_behavior:
        v = f"v{bootlog_info.mbedtls_version}" if bootlog_info.mbedtls_version else "(Behavioral Proof)"
        print(f"  {_bold('mbed TLS:'):<18s} {_cyan(v)}")
    if bootlog_info.leaked_secrets:
        print(f"  {_bold('Leaked Secrets:'):<18s} {_red(', '.join(bootlog_info.leaked_secrets))}")
    if bootlog_info.initialized_drivers:
        init_str = ", ".join(sorted(list(bootlog_info.initialized_drivers))[:5])
        if len(bootlog_info.initialized_drivers) > 5: init_str += "..."
        print(f"  {_bold('Init Drivers:'):<18s} {_cyan(init_str)}")
    if bootlog_info.kernel_subsystems:
        _fs_subsystems = {"squashfs", "jffs2", "yaffs", "ext4", "f2fs", "ubifs", "exfat", "fs_mgr"}
        active = sorted(bootlog_info.kernel_subsystems)
        active_fs     = [s for s in active if s in _fs_subsystems]
        active_kernel = [s for s in active if s not in _fs_subsystems]
        if active_kernel:
            subsys_display = ", ".join(
                _yellow(s) if s in _HIGHLIGHT_SUBSYSTEMS else s
                for s in active_kernel
            )
            print(f"  {_bold('Kern Subsys:'):<18s} {subsys_display}")
        if active_fs:
            fs_display = ", ".join(
                _yellow(s) if s in _HIGHLIGHT_SUBSYSTEMS else s
                for s in active_fs
            )
            print(f"  {_bold('File System:'):<18s} {fs_display}")
    print()

    all_matches = scan1_matches + scan2_matches
    total = len(all_matches)

    if total == 0:
        print(_bold(_green("[+] No matching CVEs found across both scans!")))
        print()
        return

    def _counts(lst):
        return {
            "critical": sum(1 for m in lst if m.severity == "CRITICAL"),
            "high":     sum(1 for m in lst if m.severity == "HIGH"),
            "medium":   sum(1 for m in lst if m.severity == "MEDIUM"),
            "low":      sum(1 for m in lst if m.severity == "LOW"),
            "unknown":  sum(1 for m in lst if m.severity not in ("CRITICAL","HIGH","MEDIUM","LOW")),
        }

    # SCAN 1
    print(_bold(_cyan("━" * width)))
    print(_bold(_cyan("  SCAN 1 — Bootloader / Firmware CVEs")))
    print(_bold(_cyan("━" * width)))
    if scan1_matches:
        c1 = _counts(scan1_matches)
        print(f"  Total: {_red(str(len(scan1_matches)))}   "
              f"{_bg_red(' CRITICAL ')} {c1['critical']}  "
              f"{_red('HIGH')} {c1['high']}  "
              f"{_yellow('MEDIUM')} {c1['medium']}  "
              f"{_green('LOW')} {c1['low']}  "
              f"{_dim('UNKNOWN')} {c1['unknown']}")
        print()
        _print_cve_table(scan1_matches, width)
        print()
        if verbose or len(scan1_matches) <= 20:
            _print_cve_details(scan1_matches, width)
    else:
        print(_bold(_green("[Scan 1] No bootloader/firmware CVEs found.")))
        print()

    if scan2_matches:
        c2 = _counts(scan2_matches)
        by_sub: dict = {}
        for m in scan2_matches:
            by_sub.setdefault(m.subsystem or "other", []).append(m)

        print(_bold(_magenta("━" * width)))
        print(_bold(_magenta("  SCAN 2 — Linux Kernel + Userspace Tool CVEs")))
        print(_bold(_magenta("━" * width)))
        print(f"  Total: {_red(str(len(scan2_matches)))}   "
              f"{_bg_red(' CRITICAL ')} {c2['critical']}  "
              f"{_red('HIGH')} {c2['high']}  "
              f"{_yellow('MEDIUM')} {c2['medium']}  "
              f"{_green('LOW')} {c2['low']}  "
              f"{_dim('UNKNOWN')} {c2['unknown']}")
        print()
        for sub, items in sorted(by_sub.items()):
            sc = _counts(items)
            label = (
                _yellow(_bold(f"{sub:<20s}"))
                if sub in _HIGHLIGHT_SUBSYSTEMS
                else _bold(f"{sub:<20s}")
            )
            print(f"    {label}  {len(items)} CVEs  "
                  f"({_bg_red(' C ')} {sc['critical']}  "
                  f"{_red('H')} {sc['high']}  "
                  f"{_yellow('M')} {sc['medium']}  "
                  f"{_green('L')} {sc['low']})")
        print()
        _print_cve_table(scan2_matches, width)
        print()
        if verbose or len(scan2_matches) <= 20:
            _print_cve_details(scan2_matches, width)
    else:
        print(_bold(_green("[Scan 2] No kernel/tool CVEs found (or versions not detected).")))
        if not bootlog_info.kernel_version:
            print(_dim("  Tip: Scan 2 requires a 'Linux version X.Y.Z' line in the bootlog."))
        print()


def generate_json_report(
    bootlog_info: BootlogInfo,
    scan1_matches: list,
    scan2_matches: list,
    output_path: str,
):
    def _serialise(m: CVEMatch) -> dict:
        return {
            "cve_id": m.cve_id, "severity": m.severity, "base_score": m.base_score,
            "published": m.published, "last_modified": m.last_modified,
            "date_risk": m.date_risk,
            "description": m.description,
            "matched_product": m.matched_product, "matched_vendor": m.matched_vendor,
            "matched_version_range": m.matched_version_range,
            "matched_components": m.matched_components, "match_stage": m.match_stage,
            "cpu_filter_result": m.cpu_filter_result, "cpu_details": m.cpu_details,
            "weaknesses": m.weaknesses, "references": m.references,
            "scan": m.scan, "subsystem": m.subsystem,
            "feature_proof": m.feature_proof,
        }

    all_matches = scan1_matches + scan2_matches
    subsystem_counts = {}
    for m in scan2_matches:
        sub = m.subsystem or "other"
        subsystem_counts[sub] = subsystem_counts.get(sub, 0) + 1

    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "system_info": {
            "bootloader_version":     bootlog_info.bootloader_version,
            "bootloader_full_string": bootlog_info.bootloader_full_string,
            "spl_version":            bootlog_info.spl_version,
            "cpu_raw":                bootlog_info.cpu_raw,
            "cpu_architecture":       bootlog_info.cpu_architecture,
            "cpu_keywords":           sorted(bootlog_info.cpu_keywords),
            "model":                  bootlog_info.model_raw,
            "filesystems":            sorted(bootlog_info.filesystems),
            "file_formats":           sorted(bootlog_info.file_formats),
            "additional_firmware":    bootlog_info.additional_firmware,
            "kernel_version":         bootlog_info.kernel_version,
            "squashfs_version":       bootlog_info.squashfs_version,
            "fuse_exfat_version":     bootlog_info.fuse_exfat_version,
            "kernel_subsystems":      sorted(list(bootlog_info.kernel_subsystems)),
        },
        "summary": {
            "total_vulnerabilities": len(all_matches),
            "scan1_total":  len(scan1_matches),
            "scan2_total":  len(scan2_matches),
            "critical": sum(1 for m in all_matches if m.severity == "CRITICAL"),
            "high":     sum(1 for m in all_matches if m.severity == "HIGH"),
            "medium":   sum(1 for m in all_matches if m.severity == "MEDIUM"),
            "low":      sum(1 for m in all_matches if m.severity == "LOW"),
            "by_subsystem": subsystem_counts,
        },
        "scan1_vulnerabilities": [_serialise(m) for m in scan1_matches],
        "scan2_vulnerabilities": [_serialise(m) for m in scan2_matches],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] JSON report saved to: {_bold(output_path)}")
    print(f"    Scan 1: {len(scan1_matches)} entries  |  "
          f"Scan 2: {len(scan2_matches)} entries  |  "
          f"Total: {len(all_matches)} entries\n")


# =============================================================================
# SECTION 9: CLI + MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Bootlog CVE Scanner with integrated CVE JSON 5.0 database sync.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--db-dir", metavar="DIR", default="db_temp", help="Path to CVE database directory")
    p.add_argument("--chunk-size", type=int, metavar="N", default=10000,
                   help="Number of CVEs to process per chunk progress report (default: 10000)")
    p.add_argument("--dry-run", action="store_true",
                   help="Preview sync without writing anything to disk")
    p.add_argument("--verbose", action="store_true",
                   help="Enable verbose/debug output")
    return p.parse_args()


def main():
    print(TOOL_BANNER)

    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── STEP 1: CVE Database Sync ──────────────────────────────────────────────
    print("=" * 60)
    print("  STEP 1 — NVD CVE Database Sync")
    print("=" * 60)
    print()

    if not getattr(args, 'db_dir', None) and not getattr(args, 'file', None):
        args.db_dir = "db_temp"
        
    cve_db_path = getattr(args, 'db_dir', "db_temp") if hasattr(args, 'db_dir') else "db_temp"


    

    # ── STEP 2: Bootlog Scan Loop ──────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  STEP 2 — Bootlog CVE Scan")
    print("=" * 60)

    while True:
        print()

        # Get bootlog path
        while True:
            bootlog_path = input("Enter path to bootlog file (.txt): ").strip().strip('"\'')
            if not bootlog_path:
                print("[!] Please enter a valid file path.")
                continue
            if not os.path.isfile(bootlog_path):
                print(f"[!] File not found: {bootlog_path}")
                continue
            break

        output_path   = input("Enter output JSON report path (or Enter to skip): ").strip().strip('"\'')
        verbose_input = input("Enable verbose output? (y/N): ").strip().lower()
        verbose       = args.verbose or (verbose_input in ("y", "yes"))

        print()
        print("[*] Parsing bootlog file...")
        start_time = time.time()
        try:
            bootlog_info = parse_bootlog(bootlog_path)
        except Exception as e:
            print(f"[!] Error parsing bootlog: {e}")
            if input("Try another bootlog? (y/N): ").strip().lower() in ("y", "yes"):
                continue
            break
        print(f"[+] Bootlog parsed in {time.time() - start_time:.2f}s")

        if not bootlog_info.bootloader_version:
            print("[!] Warning: Could not detect U-Boot version — version matching will be limited.")

        # Build Scan 2 readiness summary
        s2_ready = []
        _fs_subsystems = {"squashfs", "jffs2", "yaffs", "ext4", "f2fs", "ubifs", "exfat", "fs_mgr"}
        fs_str = ""
        if bootlog_info.kernel_version:
            kv_label = f"Kernel {bootlog_info.kernel_version}"
            if bootlog_info.kernel_build_date:
                kv_label += f" (Built: {bootlog_info.kernel_build_date})"
            active        = sorted(bootlog_info.kernel_subsystems)
            active_fs     = [s for s in active if s in _fs_subsystems]
            active_kernel = [s for s in active if s not in _fs_subsystems]
            if active_kernel:
                kv_label += f" [{', '.join(active_kernel)}]"
            s2_ready.append(kv_label)
            if active_fs:
                fs_str = f"File System: [{', '.join(active_fs)}]"

        if bootlog_info.squashfs_version:   s2_ready.append(f"SquashFS {bootlog_info.squashfs_version}")
        if bootlog_info.fuse_exfat_version: s2_ready.append(f"fuse-exfat {bootlog_info.fuse_exfat_version}")
        if bootlog_info.gcc_version:        s2_ready.append(f"GCC {bootlog_info.gcc_version}")
        if bootlog_info.tfa_version:        s2_ready.append(f"TF-A {bootlog_info.tfa_version}")
        if bootlog_info.busybox_version:
            s2_ready.append(f"BusyBox {bootlog_info.busybox_version}")
        elif bootlog_info.busybox_behavior:
            s2_ready.append(f"BusyBox (Behavioral)")
        if bootlog_info.openssl_version:    s2_ready.append(f"OpenSSL {bootlog_info.openssl_version}")
        if bootlog_info.mbedtls_version:
            s2_ready.append(f"mbed TLS {bootlog_info.mbedtls_version}")
        elif bootlog_info.mbedtls_behavior:
            s2_ready.append(f"mbed TLS (Behavioral)")

        if s2_ready:
            print(f"[+] Scan 2 targets: {', '.join(s2_ready)}")
        else:
            print("[!] Scan 2: No kernel/tool versions detected — Scan 2 will be skipped.")

        if bootlog_info.kernel_version and fs_str:
            print(f"    {fs_str}")

        print(f"\n[*] Running Unified Chunked Scans ...")
        main_bl_str = (
            f"Main Bootloader {bootlog_info.bootloader_version}"
            if bootlog_info.bootloader_version
            else "Bootloader (unknown version)"
        )
        print(f"    {main_bl_str}", end="")
        if bootlog_info.additional_firmware:
            fw_str_out = ", ".join(f"{k} {v}" for k, v in bootlog_info.additional_firmware.items())
            print(f"  |  {fw_str_out}", end="")
        print()
        
        t_start = time.time()
        scan1_matches = []
        scan2_matches = []
        chunks_processed = 0
        total_cves = 0

        try:
            for chunk in _stream_cve_database(cve_db_path, chunk_size=args.chunk_size):
                chunks_processed += 1
                total_cves += len(chunk)
                print(f"   [Progress] Processing chunk {chunks_processed} (Total CVEs: {total_cves})...")
                
                s1 = scan_bootloader_cves(bootlog_info, chunk, verbose=verbose, print_stats=False)
                scan1_matches.extend(s1)
                
                if s2_ready:
                    s2 = scan_kernel_cves(bootlog_info, chunk, verbose=verbose, print_stats=False)
                    scan2_matches.extend(s2)
        except Exception as e:
            print(f"[!] Error during chunked scan: {e}")
            break
            
        print(f"[+] Scans completed in {time.time() - t_start:.2f}s")

        generate_terminal_report(bootlog_info, scan1_matches, scan2_matches, verbose=verbose)

        if output_path:
            try:
                generate_json_report(bootlog_info, scan1_matches, scan2_matches, output_path)
            except Exception as e:
                print(f"[!] Error saving JSON report: {e}")

        print(f"Total scan time: {time.time() - start_time:.2f}s")
        print()

        if input("Scan another bootlog? (y/N): ").strip().lower() not in ("y", "yes"):
            break


if __name__ == "__main__":
    main()
def find_cve1(text: str, db_dir: str = "db_temp") -> str:
    from cv_scanner import find_cve
    return find_cve(text)
