from itertools import dropwhile
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import sys
import zipfile
import tarfile
import hashlib
import zlib
from pathlib import Path
try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    import warnings
    warnings.warn("RPi.GPIO not found or not supported on this OS. Using MockGPIO for local development.")
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
    GPIO = MockGPIO()
    
    # Globally mock RPi and RPi.GPIO for other modules that import them
    class MockRPi:
        GPIO = GPIO
    sys.modules['RPi'] = MockRPi()
    sys.modules['RPi.GPIO'] = GPIO

from time import sleep
import threading
import os
from dotenv import load_dotenv
load_dotenv()
# Project paths - extracted_files should be in Hardware_Tool root, outside Backend
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
EXTRACTED_FILES_DIR = PROJECT_ROOT / "extracted_files"
EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
ENTROPY_GRAPH_DIR = PROJECT_ROOT / "data" / "entropy_graph"
ENTROPY_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
FIRMAUDIT_DIR = PROJECT_ROOT / "FirmAudit"
FIRMAUDIT_DIR.mkdir(parents=True, exist_ok=True)

# Ensure legacy alias exists in Backend dir pointing to data/entropy_graph and FirmAudit
try:
    backend_entropy_alias = BACKEND_DIR / "entropy_graph"
    if backend_entropy_alias.is_symlink() or backend_entropy_alias.exists():
        if backend_entropy_alias.is_symlink() and backend_entropy_alias.resolve() != ENTROPY_GRAPH_DIR.resolve():
            backend_entropy_alias.unlink()
            backend_entropy_alias.symlink_to(ENTROPY_GRAPH_DIR, target_is_directory=True)
    elif not backend_entropy_alias.exists():
        backend_entropy_alias.symlink_to(ENTROPY_GRAPH_DIR, target_is_directory=True)
except Exception:
    pass

try:
    backend_firmaudit_alias = BACKEND_DIR / "FirmAudit"
    if not backend_firmaudit_alias.exists():
        backend_firmaudit_alias.symlink_to(FIRMAUDIT_DIR, target_is_directory=True)
except Exception:
    pass

import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from bruteforce_uart import check_login
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
import subprocess
import httpx
import asyncio
from typing import Optional
from collect_files import collect_all_files, get_search_results_json
from typing import List
import shutil
from datetime import datetime
from ChatBot import generate_answer,reindex_database
from assistant_rag import ask_assistant, index_guide
from BootLog_Summary import summarize_boot_log
from Agent_Analyze import run
from EPSS_CVSS_Extract import compute_vulnerabilities
from EPSS_CVSS_Extract_new import compute_vulnerabilities1
from new_capture_uart_boot import new_capture_boot_output
from new_detect_baud import new_run_baud_detection
from Hardcoded_Password import FirmwareScanner
import time
import re
from scanner_wrapper import run_scan, run_scan_content
from cv_scanner import find_cve, scan_bootlog_nvd
from firmaudit_parser import parse_firmaudit_report, get_firmaudit_report_data

from hardware_config import (
    RELAY_POWER_PIN,
    OCTOCOUPLER_POWER_PIN,
    CHANNEL_PIN,
    VOLTAGE_GLITCH_PIN,
    get_uart_port,
    get_hardware_diagnostics,
    get_gpio,
    IS_PI_5
)

# ---------------- CONFIG ---------------- #
switching_pin = RELAY_POWER_PIN
channel_pin = CHANNEL_PIN
volt_pin = VOLTAGE_GLITCH_PIN
relay_pin = OCTOCOUPLER_POWER_PIN

FIRM_DIR = "extracted_firm"
LOG_DIR = "uart_logs"

# Global power thread
power_thread = None

# Safe GPIO provider
GPIO = get_gpio()

# ---------------- FASTAPI ---------------- #
app = FastAPI()

# ---------------- STARTUP / SHUTDOWN ---------------- #
@app.on_event("startup")
def startup():    
    global power_thread

    print("[INFO] Initializing GPIO...")

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)

    GPIO.setup(volt_pin, GPIO.OUT)
    GPIO.setup(relay_pin, GPIO.OUT)
    GPIO.setup(switching_pin, GPIO.OUT)
    GPIO.setup(channel_pin, GPIO.OUT)

    GPIO.output(relay_pin, GPIO.HIGH)

    print("[INFO] Starting PowerMod thread...")
    power_thread = PowerMod(switching_pin=switching_pin, channel_pin=channel_pin)
    power_thread.start()

@app.on_event("shutdown")
def shutdown():
    global power_thread

    print("[INFO] Cleaning up GPIO...")

    if power_thread:
        try:
            if hasattr(power_thread, "stop"):
                power_thread.stop()
            power_thread.join(timeout=1.0)
        except Exception as e:
            print(f"[Warning] Error stopping power thread: {e}")

    try:
        GPIO.cleanup()
    except Exception:
        pass

# ---------------- CORS ---------------- #
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000","http://localhost:3008","http://localhost:3004","http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- STATIC FILES ---------------- #
EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
FIRMAUDIT_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/files", StaticFiles(directory=str(EXTRACTED_FILES_DIR)), name="files")
app.mount("/entropy_graph", StaticFiles(directory=str(ENTROPY_GRAPH_DIR)), name="entropy_graph")
app.mount("/FirmAudit", StaticFiles(directory=str(FIRMAUDIT_DIR)), name="FirmAudit")



# ---------------- MODELS ---------------- #
class BootLog(BaseModel):
    boot_log: str


# ---------------- ROUTES ---------------- #

@app.get('/')
def home():
    return {"message": "hello"}


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), script: str = Form("binwalk"), firmAuditOption: str = Form(None), block_size: int = Form(None)):
    EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
    ENTROPY_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    filename = file.filename
    file_path = str(EXTRACTED_FILES_DIR / filename)

    # Save the uploaded file temporarily for analysis
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    try:
        firmaudit_script = os.path.join(os.path.dirname(__file__) or ".", "FirmAudit.py")

        base_name = os.path.splitext(filename)[0]

        if script == "binwalk":
            try:
                result = subprocess.run(
                    ["binwalk", "-e", "--directory", str(EXTRACTED_FILES_DIR), file_path],
                    capture_output=True, text=True, check=True
                )
                binwalk_log_path = EXTRACTED_FILES_DIR / f"{base_name}_binwalk.txt"
                with open(binwalk_log_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)

                extracted_folder = EXTRACTED_FILES_DIR / f"_{base_name}.extracted"
                saved_path = str(extracted_folder) if extracted_folder.exists() else str(binwalk_log_path)
                return {
                    "output": result.stdout,
                    "saved_path": saved_path,
                    "saved_dir": str(EXTRACTED_FILES_DIR),
                    "extracted_dir": str(extracted_folder) if extracted_folder.exists() else None,
                    "log_file": str(binwalk_log_path)
                }
            except FileNotFoundError:
                return {"error": "binwalk tool not found on this system. Please install binwalk or use FirmAudit."}

        elif script == "FirmAudit":
            if firmAuditOption == "-info":
                # Run FirmAudit.py with -info flag and save output to EXTRACTED_FILES_DIR (outside backend)
                result = subprocess.run(
                    [sys.executable, firmaudit_script, file_path, "-info"],
                    capture_output=True, text=True, check=True
                )
                info_output_path = EXTRACTED_FILES_DIR / f"{base_name}_info.txt"
                with open(info_output_path, "w", encoding="utf-8") as f:
                    f.write(result.stdout)

                return {
                    "output": result.stdout,
                    "saved_path": str(info_output_path),
                    "saved_dir": str(EXTRACTED_FILES_DIR),
                    "log_file": str(info_output_path)
                }
            elif firmAuditOption == "extract":
                # Run FirmAudit.py without -info flag (Extract and Analyze)
                result = subprocess.run(
                    [sys.executable, firmaudit_script, file_path],
                    cwd=str(BACKEND_DIR),
                    capture_output=True, text=True, check=True
                )

                # Save ONLY <filename>.txt directly inside Hardware_Tool/FirmAudit/
                target_txt_file = FIRMAUDIT_DIR / f"{base_name}.txt"
                target_extracted_dir = EXTRACTED_FILES_DIR / f"{base_name}_extracted"

                # Check and move extracted directory to EXTRACTED_FILES_DIR
                extracted_candidates = [
                    BACKEND_DIR / f"{base_name}_extracted",
                    Path(f"{base_name}_extracted"),
                    PROJECT_ROOT / f"{base_name}_extracted",
                ]
                for cand in extracted_candidates:
                    if cand.exists() and cand.resolve() != target_extracted_dir.resolve():
                        if target_extracted_dir.exists():
                            shutil.rmtree(str(target_extracted_dir))
                        shutil.move(str(cand), str(target_extracted_dir))
                        break

                # Locate raw testout file produced by FirmAudit
                testout_candidates = [
                    BACKEND_DIR / f"{base_name}_testout.txt",
                    Path(f"{base_name}_testout.txt"),
                    PROJECT_ROOT / f"{base_name}_testout.txt",
                    EXTRACTED_FILES_DIR / f"{base_name}_testout.txt",
                ]
                raw_testout_found = None
                for cand in testout_candidates:
                    if cand.exists():
                        raw_testout_found = cand
                        break

                # Read testout file content
                txt_output = ""
                if raw_testout_found and raw_testout_found.exists():
                    with open(raw_testout_found, "r", encoding="utf-8", errors="replace") as txt_file:
                        txt_output = txt_file.read()
                    try:
                        raw_testout_found.unlink()
                    except Exception:
                        pass
                elif result.stdout:
                    txt_output = result.stdout
                else:
                    txt_output = "No vulnerability audit output generated."

                # Save directly into Hardware_Tool/FirmAudit/<filename>.txt (.txt only)
                with open(target_txt_file, "w", encoding="utf-8") as txt_f:
                    txt_f.write(txt_output)

                # Also save a copy of the testout file in EXTRACTED_FILES_DIR as usual
                extracted_testout_file = EXTRACTED_FILES_DIR / f"{base_name}_testout.txt"
                try:
                    with open(extracted_testout_file, "w", encoding="utf-8") as out_f:
                        out_f.write(txt_output)
                except Exception:
                    pass

                # Check if the extracted directory exists
                extracted_dir_message = ""
                if target_extracted_dir.exists():
                    extracted_dir_message = f"Extracted files can be found in {target_extracted_dir}."
                else:
                    extracted_dir_message = "Error: Extracted directory not found."

                saved_path = str(target_txt_file)
                audit_results = parse_firmaudit_report(txt_output)

                return {
                    "extracted_dir": str(target_extracted_dir) if target_extracted_dir.exists() else None,
                    "extracted_dir_message": extracted_dir_message,
                    "txt_output": txt_output,
                    "audit_results": audit_results,
                    "saved_path": saved_path,
                    "saved_dir": str(FIRMAUDIT_DIR),
                    "log_file": str(target_txt_file),
                    "txt_url": f"/FirmAudit/{base_name}.txt"
                }

        elif script in ["entropy", "extractor"]:
            base_name = os.path.splitext(filename)[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            folder_name = f"{base_name}_{timestamp}"
            scan_output_dir = ENTROPY_GRAPH_DIR / folder_name
            scan_output_dir.mkdir(parents=True, exist_ok=True)

            if script == "entropy":
                cmd = [
                    sys.executable, firmaudit_script, file_path,
                    "-E", "--output_dir", str(scan_output_dir)
                ]
            else:
                bs = block_size if (block_size is not None and block_size > 0) else 1024
                cmd = [
                    sys.executable, firmaudit_script, file_path,
                    "-B", str(bs), "--output_dir", str(scan_output_dir)
                ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            txt_output_path = scan_output_dir / f"{base_name}_entropy.txt"
            html_output_path = scan_output_dir / f"{base_name}_entropy.html"
            png_output_path = scan_output_dir / f"{base_name}_entropy.png"

            # Check potential locations and ensure stored in scan_output_dir
            for candidate_dir in [Path.cwd(), BACKEND_DIR, PROJECT_ROOT, ENTROPY_GRAPH_DIR, PROJECT_ROOT / "data" / "entropy_graph", PROJECT_ROOT / "entropy_graph"]:
                c_html = candidate_dir / f"{base_name}_entropy.html"
                c_txt = candidate_dir / f"{base_name}_entropy.txt"
                c_png = candidate_dir / f"{base_name}_entropy.png"

                if c_html.resolve() != html_output_path.resolve() and c_html.exists():
                    shutil.copy2(str(c_html), str(html_output_path))
                    try:
                        c_html.unlink()
                    except Exception:
                        pass
                if c_txt.resolve() != txt_output_path.resolve() and c_txt.exists():
                    shutil.copy2(str(c_txt), str(txt_output_path))
                    try:
                        c_txt.unlink()
                    except Exception:
                        pass
                if c_png.resolve() != png_output_path.resolve() and c_png.exists():
                    shutil.copy2(str(c_png), str(png_output_path))
                    try:
                        c_png.unlink()
                    except Exception:
                        pass

            if html_output_path.exists():
                txt_content = ""
                if txt_output_path.exists():
                    with open(txt_output_path, "r", encoding="utf-8", errors="replace") as txt_file:
                        txt_content = txt_file.read()
                with open(html_output_path, "r", encoding="utf-8", errors="replace") as html_file:
                    html_content = html_file.read()
                return {
                    "base_name": base_name,
                    "folder_name": folder_name,
                    "txt_output": txt_content,
                    "html_output": html_content,
                    "graph_path": str(html_output_path),
                    "graph_url": f"/entropy_graph/{folder_name}/{base_name}_entropy.html",
                    "png_url": f"/entropy_graph/{folder_name}/{base_name}_entropy.png" if png_output_path.exists() else None,
                    "txt_url": f"/entropy_graph/{folder_name}/{base_name}_entropy.txt" if txt_output_path.exists() else None,
                    "entropy_dir": str(scan_output_dir),
                    "saved_path": str(scan_output_dir),
                    "saved_dir": str(scan_output_dir)
                }
            else:
                return {"error": "Entropy output files not generated.", "output": result.stdout}

        else:
            return {"error": "Invalid script selected."}

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else (e.stdout.strip() if e.stdout else str(e))
        print(f"Error running {script}: {err_msg}")
        return {"error": err_msg}
    except FileNotFoundError as fnf:
        print(f"FileNotFoundError in {script}: {fnf}")
        return {"error": f"Tool or script not found: {str(fnf)}"}
    except Exception as e:
        print(f"Exception running {script}: {e}")
        return {"error": str(e)}
    finally:
        # Clean up temporary uploaded file from storage
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"[INFO] Removed uploaded file from temp storage: {file_path}")
            except Exception as e:
                print(f"[WARNING] Failed to remove uploaded file {file_path}: {e}")

@app.get("/latest-entropy-graph/")
async def get_latest_entropy_graph():
    """
    Endpoint: Returns metadata and URLs for the most recently generated entropy graph in data/entropy_graph.
    """
    if not ENTROPY_GRAPH_DIR.exists():
        return {"found": False}

    subdirs = [d for d in ENTROPY_GRAPH_DIR.iterdir() if d.is_dir()]
    if not subdirs:
        return {"found": False}

    subdirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    for latest_dir in subdirs:
        html_files = list(latest_dir.glob("*_entropy.html"))
        if html_files:
            html_file = html_files[0]
            folder_name = latest_dir.name
            base_name = html_file.name.replace("_entropy.html", "")
            png_file = latest_dir / f"{base_name}_entropy.png"
            txt_file = latest_dir / f"{base_name}_entropy.txt"
            return {
                "found": True,
                "base_name": base_name,
                "folder_name": folder_name,
                "entropy_dir": str(latest_dir),
                "graph_url": f"/entropy_graph/{folder_name}/{html_file.name}",
                "png_url": f"/entropy_graph/{folder_name}/{png_file.name}" if png_file.exists() else None,
                "txt_url": f"/entropy_graph/{folder_name}/{txt_file.name}" if txt_file.exists() else None,
            }

    return {"found": False}


@app.get("/firmaudit-report/{base_name}")
async def get_firmaudit_report(base_name: str):
    """
    Endpoint: Returns parsed vulnerability audit results for an existing FirmAudit report.
    """
    return get_firmaudit_report_data(base_name, [FIRMAUDIT_DIR, EXTRACTED_FILES_DIR, PROJECT_ROOT, BACKEND_DIR])




@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate: int, power_cycle_delay: int):
    try:
        best_baud = await asyncio.to_thread(
            detect_baud.run_baud_detection,
            sampling_rate,
            power_cycle_delay,
            power_thread
        )

        output = ""
        if os.path.exists(detect_baud.OUTPUT_FILE):
            try:
                with open(detect_baud.OUTPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
                    output = f.read()
            except Exception:
                output = ""

        return {
            "best_baud": best_baud,
            "log": output
        }
    except Exception as e:
        return {
            "best_baud": None,
            "error": str(e),
            "log": f"Detection error: {str(e)}"
        }

@app.get("/new_detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def new_baud_detect(sampling_rate: int, power_cycle_delay: int):
    try:
        from new_detect_baud import new_run_baud_detection, OUTPUT_FILE as NEW_BAUD_OUTPUT_FILE
        best_baud = await asyncio.to_thread(
            new_run_baud_detection,
            sampling_rate,
            power_cycle_delay,
            power_thread
        )

        output = ""
        target_out = NEW_BAUD_OUTPUT_FILE if os.path.exists(NEW_BAUD_OUTPUT_FILE) else detect_baud.OUTPUT_FILE
        if os.path.exists(target_out):
            try:
                with open(target_out, "r", encoding="utf-8", errors="replace") as f:
                    output = f.read()
            except Exception:
                output = ""

        return {
            "best_baud": best_baud,
            "log": output
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "best_baud": None,
            "error": str(e),
            "log": f"Detection error: {str(e)}"
        }
    
# =====================================================================
# Legacy Voltage Glitcher (Relay / PowerMod) Endpoints
# =====================================================================

@app.get("/switch_power/{flag}")
async def switch_power(flag: int):
    try:
        if flag == 0:
            power_thread.set_state(1)
            msg = "Power set to state 0 (OFF)"
        else:
            power_thread.set_state(0)
            msg = "Power set to state 1 (ON)"
        return {"status": "ok", "message": msg, "flag": flag}
    except Exception as e:
        return {"status": "error", "message": f"Failed to toggle power: {str(e)}"}

@app.get("/set_volt/{freq}")
async def set_volt(freq: int):
    try:
        power_thread.unset_state()
        power_thread.set_delay(freq)
        return {"status": "ok", "message": f"Frequency set to {freq} Hz"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to set voltage frequency: {str(e)}"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon: int, poff: int):
    try:
        power_thread.unset_state()
        power_thread.set_poweroff(int(poff))
        power_thread.set_poweron(int(pon))
        return {"status": "ok", "data": "OK _pon", "message": f"Custom pulse timing set: ON={pon}ms, OFF={poff}ms"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to set custom pulse: {str(e)}"}

@app.get("/set_channel/{channel}")
async def set_channel(channel: int):
    try:
        power_thread.set_channel(channel)
        return {"status": "ok", "message": f"Channel set to {channel}"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to set channel: {str(e)}"}

# =====================================================================
# Hardware Info Diagnostics
# =====================================================================

@app.get("/hardware/info")
async def hardware_info():
    """Returns system architecture diagnostics and pin mapping for Raspberry Pi 5."""
    return get_hardware_diagnostics()

# =====================================================================
# New Voltage Glitcher (Octocoupler) Endpoints
# Note: Frequency tuning and channel selection are omitted as the
# octocoupler uses direct pulse timing and a dedicated single pin.
# =====================================================================

@app.get("/new_switch_power/{flag}")
async def new_switch_power(flag: int):
    try:
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(OCTOCOUPLER_POWER_PIN, GPIO.OUT)

        if flag == 0:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.HIGH)
            msg = "Octocoupler power set to OFF"
        else:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.LOW)
            msg = "Octocoupler power set to ON"

        return {"status": "ok", "message": msg, "flag": flag}
    except Exception as e:
        return {"status": "error", "message": f"Failed to switch octocoupler power: {str(e)}"}

# Global holder for custom glitch loop thread
_glitch_worker = None
_glitch_stop_flag = threading.Event()

def _run_octocoupler_glitch(pon_sec: float, poff_sec: float, total_sec: float):
    global _glitch_stop_flag
    _glitch_stop_flag.clear()
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(OCTOCOUPLER_POWER_PIN, GPIO.OUT)

    start_time = time.time()
    try:
        while time.time() - start_time < total_sec and not _glitch_stop_flag.is_set():
            # Power ON (Device ON is LOW)
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.LOW)
            time.sleep(pon_sec)
            if _glitch_stop_flag.is_set():
                break
            # Power OFF (Device OFF is HIGH)
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.HIGH)
            time.sleep(poff_sec)
    except Exception as e:
        print(f"[ERROR] Octocoupler glitch loop exception: {e}")
    finally:
        try:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.LOW)
        except Exception:
            pass

@app.get("/new_set_volt_custom/{pon}/{poff}/{duration}")
async def new_volt_glitch_custom(pon: float, poff: float, duration: float):
    global _glitch_worker, _glitch_stop_flag
    try:
        duration_seconds = float(duration) * 60
        pon_sec = float(pon)
        poff_sec = float(poff)

        # Stop any existing glitch thread before starting a new one
        _glitch_stop_flag.set()
        if _glitch_worker and _glitch_worker.is_alive():
            _glitch_worker.join(timeout=1.0)

        _glitch_worker = threading.Thread(
            target=_run_octocoupler_glitch,
            args=(pon_sec, poff_sec, duration_seconds),
            daemon=True
        )
        _glitch_worker.start()

        return {
            "status": "running",
            "message": f"Glitch cycle active in background for {duration} minute(s) (ON={pon}s, OFF={poff}s)",
            "duration_seconds": duration_seconds
        }
    except Exception as e:
        return {"status": "error", "message": f"Failed to start octocoupler glitch: {str(e)}"}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def capture_boot(sampling_rate: int, power_cycle: int, baud_rate: int):
    try:
        output = capture_uart_boot.main(
            baud_rate,
            sampling_rate,
            power_cycle,
        )

        directory = os.getenv("BOOTLOGS_DIR", "../data/bootlogs")
        if not os.path.isabs(directory):
            directory = os.path.abspath(os.path.join(os.path.dirname(__file__), directory))

        os.makedirs(directory, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"boot_log_{timestamp}.txt"
        full_path = os.path.join(directory, filename)

        with open(full_path, "w", encoding="utf-8") as file:
            if isinstance(output, (dict, list)):
                import json
                json.dump(output, file, indent=4)
            else:
                file.write(str(output))

        is_error = isinstance(output, str) and output.startswith("[ERROR]")

        return {
            "success": not is_error,
            "data": output,
            "filename": filename,
            "saved_path": full_path,
            "error": output if is_error else None
        }
    except Exception as e:
        return {
            "success": False,
            "data": f"Error during boot capture: {str(e)}",
            "error": str(e)
        }

@app.get("/new_capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def new_capture_boot(sampling_rate: int, power_cycle: int, baud_rate: int):
    try:
        output = new_capture_boot_output(
            baud_rate,
            sampling_rate,
            power_cycle,
        )

        directory = os.getenv("BOOTLOGS_DIR", "../data/bootlogs")
        if not os.path.isabs(directory):
            directory = os.path.abspath(os.path.join(os.path.dirname(__file__), directory))

        os.makedirs(directory, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"boot_log_{timestamp}.txt"
        full_path = os.path.join(directory, filename)

        with open(full_path, "w", encoding="utf-8") as file:
            if isinstance(output, (dict, list)):
                import json
                json.dump(output, file, indent=4)
            else:
                file.write(str(output))

        is_error = isinstance(output, str) and output.startswith("[ERROR]")

        return {
            "success": not is_error,
            "data": output,
            "filename": filename,
            "saved_path": full_path,
            "error": output if is_error else None
        }
    except Exception as e:
        return {
            "success": False,
            "data": f"Error during octocoupler boot capture: {str(e)}",
            "error": str(e)
        }

@app.get("/check_uart_console/{baud}")
async def uart_console(
    baud: int = 115200,
    power_delay: int = 3,
    listen_time: int = 5,
    mode: str = "relay",
    attempt_uboot_breakout: bool = True
):
    try:
        res = check_uart_console.main(
            baud_rate=baud,
            power_thread=power_thread,
            power_delay=power_delay,
            listen_time=listen_time,
            mode=mode,
            attempt_uboot_breakout=attempt_uboot_breakout
        )
        return res
    except Exception as e:
        return {
            "success": False,
            "is_available": False,
            "status": "error",
            "console_type": "error",
            "data": f"Error: {str(e)}",
            "message": str(e),
            "log": str(e)
        }

@app.get("/new_check_uart_console/{baud}")
async def new_uart_console(
    baud: int = 115200,
    power_delay: int = 3,
    listen_time: int = 5,
    attempt_uboot_breakout: bool = True
):
    try:
        res = check_uart_console.main(
            baud_rate=baud,
            power_thread=power_thread,
            power_delay=power_delay,
            listen_time=listen_time,
            mode="octocoupler",
            attempt_uboot_breakout=attempt_uboot_breakout
        )
        return res
    except Exception as e:
        return {
            "success": False,
            "is_available": False,
            "status": "error",
            "console_type": "error",
            "data": f"Error: {str(e)}",
            "message": str(e),
            "log": str(e)
        }

@app.post("/cv_scan/")
async def cv_scan(boot_log: BootLog):
    try:
        scan_results = run_scan_content(boot_log.boot_log, filename="captured_bootlog.txt")
        first_res = scan_results["results"][0] if scan_results.get("results") else {}
        matches = first_res.get("matches", [])
        cve_count = first_res.get("cve_count", len(matches))

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNRATED": 0}
        for m in matches:
            sev = (m.get("severity") or "UNRATED").upper()
            if sev.startswith("CRIT"):
                severity_counts["CRITICAL"] += 1
            elif sev.startswith("HIGH"):
                severity_counts["HIGH"] += 1
            elif sev.startswith("MED"):
                severity_counts["MEDIUM"] += 1
            elif sev.startswith("LOW"):
                severity_counts["LOW"] += 1
            else:
                severity_counts["UNRATED"] += 1

        # Also provide formatted ASCII text for backward compatibility
        report_text = ""
        try:
            from cv_scanner import scan_bootlog_nvd
            text_res = scan_bootlog_nvd(boot_log.boot_log)
            report_text = text_res.get("report_text", "")
        except Exception:
            report_text = first_res.get("summary_text", "")

        return {
            "success": True,
            "data": report_text or "Analysis complete. No vulnerabilities reported.",
            "scan_data": scan_results,
            "vulnerabilities": matches,
            "summary": first_res.get("device_summary", {}),
            "cve_count": cve_count,
            "severity_breakdown": severity_counts,
            "database": "NIST National Vulnerability Database (NVD 2.0)"
        }
    except Exception as e:
        return {
            "success": False,
            "data": f"Scan error: {str(e)}",
            "scan_data": None,
            "vulnerabilities": [],
            "summary": {},
            "cve_count": 0,
            "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNRATED": 0},
            "database": "NIST National Vulnerability Database (NVD 2.0)"
        }


@app.get("/list-files/")
async def list_files():
    EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
    return os.listdir(str(EXTRACTED_FILES_DIR))


def _format_browser_file_size(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "--"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} kB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def _get_browser_file_type(name: str, is_dir: bool) -> str:
    if is_dir:
        return "Folder"
    name_lower = name.lower()
    if name_lower.endswith((".tar.gz", ".tgz", ".tar", ".zip", ".7z", ".gz", ".bz2", ".xz")):
        return "Archive"
    elif name_lower.endswith((".bin", ".img", ".rom", ".elf", ".hex")):
        return "Binary"
    elif name_lower.endswith((".txt", ".log", ".md")):
        return "Text"
    elif name_lower.endswith((".conf", ".cfg", ".ini", ".yaml", ".yml", ".json")) or name_lower in ("passwd", "shadow", "htpasswd"):
        return "Configuration"
    elif name_lower.endswith((".py", ".sh", ".bash", ".js")):
        return "Script"
    elif "." in name:
        return f"{name.rsplit('.', 1)[-1].upper()} File"
    return "File"

def _format_browser_mtime(mtime_epoch: float) -> str:
    if not mtime_epoch:
        return "--"
    try:
        dt = datetime.fromtimestamp(mtime_epoch)
        now = datetime.now()
        diff_days = (now.date() - dt.date()).days
        if diff_days == 0:
            return f"Today {dt.strftime('%H:%M')}"
        elif diff_days == 1:
            return "Yesterday"
        elif diff_days < 7:
            return dt.strftime("%a")
        elif dt.year == now.year:
            return dt.strftime("%b %d")
        else:
            return dt.strftime("%b %d, %Y")
    except Exception:
        return "--"


@app.get("/browse-directory")
async def browse_directory(path: Optional[str] = Query(None, description="Directory path to browse")):
    """
    Browse server-side directories and files formatted identically to the desktop
    GTK File Explorer (Name, Size, Type, Modified, Sidebar Places).
    """
    try:
        if path and path.strip():
            candidate = Path(path.strip()).expanduser().resolve()
            if candidate.exists():
                target_path = candidate
            else:
                rel_candidate = (PROJECT_ROOT / path.strip()).resolve()
                if rel_candidate.exists():
                    target_path = rel_candidate
                else:
                    target_path = EXTRACTED_FILES_DIR.resolve()
        else:
            target_path = EXTRACTED_FILES_DIR.resolve()

        EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
        if not target_path.exists():
            target_path = EXTRACTED_FILES_DIR.resolve()

        if target_path.is_file():
            target_dir = target_path.parent
        else:
            target_dir = target_path

        directories = []
        files = []

        try:
            with os.scandir(target_dir) as it:
                for entry in it:
                    if entry.name.startswith("."):
                        continue
                    try:
                        stat_info = entry.stat()
                    except Exception:
                        stat_info = None

                    is_d = entry.is_dir()
                    count = 0
                    if is_d:
                        try:
                            with os.scandir(entry.path) as sub_it:
                                count = sum(1 for sub in sub_it if not sub.name.startswith("."))
                        except Exception:
                            count = 0

                    size_val = stat_info.st_size if (stat_info and not is_d) else 0
                    mtime_val = stat_info.st_mtime if stat_info else 0

                    item_info = {
                        "name": entry.name,
                        "path": str(Path(entry.path).resolve()),
                        "is_dir": is_d,
                        "size": size_val,
                        "formatted_size": f"{count} items" if is_d else _format_browser_file_size(size_val),
                        "type": _get_browser_file_type(entry.name, is_d),
                        "mtime": mtime_val,
                        "formatted_mtime": _format_browser_mtime(mtime_val),
                        "item_count": count if is_d else 0,
                    }
                    if is_d:
                        directories.append(item_info)
                    else:
                        files.append(item_info)
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied reading directory.")

        directories.sort(key=lambda x: x["name"].lower())
        files.sort(key=lambda x: x["name"].lower())

        parent_path = str(target_dir.parent.resolve()) if target_dir.parent != target_dir else None

        home_dir = Path.home()
        sidebar_places = [
            {"name": "Recent", "icon": "recent", "path": str(EXTRACTED_FILES_DIR.resolve())},
            {"name": "Home", "icon": "home", "path": str(home_dir.resolve())},
            {"name": "Documents", "icon": "documents", "path": str((home_dir / "Documents").resolve()) if (home_dir / "Documents").exists() else str(home_dir.resolve())},
            {"name": "Downloads", "icon": "downloads", "path": str((home_dir / "Downloads").resolve()) if (home_dir / "Downloads").exists() else str(home_dir.resolve())},
            {"name": "Music", "icon": "music", "path": str((home_dir / "Music").resolve()) if (home_dir / "Music").exists() else str(home_dir.resolve())},
            {"name": "Pictures", "icon": "pictures", "path": str((home_dir / "Pictures").resolve()) if (home_dir / "Pictures").exists() else str(home_dir.resolve())},
            {"name": "Videos", "icon": "videos", "path": str((home_dir / "Videos").resolve()) if (home_dir / "Videos").exists() else str(home_dir.resolve())},
            {"name": "extracted_files", "icon": "archive", "path": str(EXTRACTED_FILES_DIR.resolve())},
            {"name": "FirmAudit", "icon": "archive", "path": str(FIRMAUDIT_DIR.resolve())},
            {"name": "Hardware_Tool", "icon": "project", "path": str(PROJECT_ROOT.resolve())},
            {"name": "Other Locations", "icon": "computer", "path": "/"},
        ]

        return {
            "success": True,
            "current_path": str(target_dir.resolve()),
            "parent_path": parent_path,
            "sidebar_places": sidebar_places,
            "directories": directories,
            "files": files,
            "total_items": len(directories) + len(files),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error browsing directory: {str(e)}")


@app.post("/pick-native-folder")
async def pick_native_folder(initial_dir: Optional[str] = Query(None)):
    """
    Spawns the native Linux GTK file / folder chooser (Zenity) directly on DISPLAY :0.
    Returns the selected absolute path to the web UI.
    """
    try:
        env = os.environ.copy()
        if "DISPLAY" not in env or not env["DISPLAY"]:
            env["DISPLAY"] = ":0"
        if "WAYLAND_DISPLAY" not in env or not env["WAYLAND_DISPLAY"]:
            env["WAYLAND_DISPLAY"] = "wayland-0"
        if "XAUTHORITY" not in env and os.path.exists("/home/hardware-security/.Xauthority"):
            env["XAUTHORITY"] = "/home/hardware-security/.Xauthority"

        init_path = initial_dir if initial_dir and os.path.exists(initial_dir) else str(EXTRACTED_FILES_DIR.resolve())
        cmd = [
            "zenity",
            "--file-selection",
            "--directory",
            "--title=Select Folder (Hardware Auditing Tool)",
            f"--filename={init_path}/"
        ]

        def run_zenity():
            try:
                p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
                if p.returncode == 0 and p.stdout.strip():
                    return {"success": True, "path": p.stdout.strip(), "cancelled": False}
                return {"success": False, "path": None, "cancelled": True}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Dialog timed out", "cancelled": True}
            except Exception as ex:
                return {"success": False, "error": str(ex), "cancelled": False}

        return await asyncio.to_thread(run_zenity)
    except Exception as e:
        return {"success": False, "error": str(e), "cancelled": False}


class OpenFolderRequest(BaseModel):
    path: str


@app.post("/open-native-folder")
async def open_native_folder_endpoint(payload: OpenFolderRequest):
    """
    Opens the specified folder (or parent directory of a file) in the native Linux
    file manager (e.g. pcmanfm / nautilus via xdg-open) on DISPLAY :0.
    """
    try:
        raw_path = payload.path.strip()
        if not raw_path:
            raise HTTPException(status_code=400, detail="Path cannot be empty.")

        target = Path(raw_path).resolve()
        if not target.exists():
            if target.parent.exists():
                target = target.parent
            else:
                raise HTTPException(status_code=404, detail=f"Path '{raw_path}' does not exist.")

        folder_to_open = target if target.is_dir() else target.parent

        env = os.environ.copy()
        if "DISPLAY" not in env or not env["DISPLAY"]:
            env["DISPLAY"] = ":0"
        if "WAYLAND_DISPLAY" not in env or not env["WAYLAND_DISPLAY"]:
            env["WAYLAND_DISPLAY"] = "wayland-0"
        if "XAUTHORITY" not in env and os.path.exists("/home/hardware-security/.Xauthority"):
            env["XAUTHORITY"] = "/home/hardware-security/.Xauthority"

        subprocess.Popen(["xdg-open", str(folder_to_open)], env=env)

        return {
            "success": True,
            "opened_path": str(folder_to_open),
            "original_path": str(target)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to open native file explorer: {str(e)}")


FIRM_DIR = os.getenv("FIRM_DIR", str(EXTRACTED_FILES_DIR))

@app.get("/files/{filename}")
@app.get("/download_firm/{filename}")
def download_firm(filename: str):
    file_path = os.path.join(FIRM_DIR, f"{filename}.bin")
    if not os.path.exists(file_path):
        file_path = os.path.join(FIRM_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Firmware file '{filename}' not found.")
    return FileResponse(file_path)


@app.post("/uploadfile/")
async def brute_force(file: UploadFile, baud_rate: int):
    upload_dir = os.getenv("UPLOADS_DIR", "../data/uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)

    with open(file_path, "wb") as f:
        f.write(await file.read())

    fail_key = "Invalid Password"

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for cred in f:
            if check_login(baud_rate, fail_key, cred.strip()):
                return {"data": cred.strip()}

    return {"data": "No Credentials match"}
    

class CVERequest(BaseModel):
    cves: List[str]

@app.post("/cves")
async def cves_endpoint(upload_file: UploadFile = File(...)): 
    """
    Accepts a bootlog file from the frontend, saves it temporarily, 
    and passes it to the EPSS/CVSS extraction script for analysis.
    """

    temp_input_file = f"temp_{upload_file.filename}"
    output_text_file = f"output_{upload_file.filename}.txt" 
    
    try:
        content = await upload_file.read()
        
        with open(temp_input_file, "wb") as f:
            f.write(content)
            

        temp = content.decode("utf-8", errors="replace") 
        
        output = find_cve(temp)
        
        with open(output_text_file, "w", encoding="utf-8") as out_f:
            out_f.write(output)
            
        data = compute_vulnerabilities(output_text_file)
        if not data:
            data = []

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to compute vulnerabilities: {str(e)}"
        )
        
    finally:
        if os.path.exists(temp_input_file):
            try: os.remove(temp_input_file)
            except Exception: pass
        if os.path.exists(output_text_file):
            try: os.remove(output_text_file)
            except Exception: pass

    return JSONResponse({"vulnerabilities": data})
    
@app.post("/new_cves")
async def new_cves_endpoint(upload_file: UploadFile = File(...)): 
    """
    Accepts a bootlog file from the frontend, saves it temporarily, 
    and passes it to the EPSS/CVSS extraction script for analysis.
    """

    temp_input_file = f"temp_{upload_file.filename}"
    output_text_file = f"output_{upload_file.filename}.txt" 
    
    try:
        content = await upload_file.read()
        
        with open(temp_input_file, "wb") as f:
            f.write(content)
            

        temp = content.decode("utf-8", errors="replace") 
        
        output = find_cve(temp)
        
        with open(output_text_file, "w", encoding="utf-8") as out_f:
            out_f.write(output)
            
        data = compute_vulnerabilities1(output_text_file)
        if not data:
            data = []

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to compute vulnerabilities: {str(e)}"
        )
        
    finally:
        if os.path.exists(temp_input_file):
            try: os.remove(temp_input_file)
            except Exception: pass
        if os.path.exists(output_text_file):
            try: os.remove(output_text_file)
            except Exception: pass

    return JSONResponse({"vulnerabilities": data})
    
_BACKEND_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = str((_BACKEND_DIR / os.getenv("UPLOADS_DIR", "../data/uploads")).resolve())
MERGED_FILE = str((_BACKEND_DIR / "combined_files_output.txt").resolve())

@app.post("/process-files/")
async def process_multiple_files(files: list[UploadFile] = File(...)):
    # 1. Clear contents of the upload directory safely without removing the folder
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    for item in os.listdir(UPLOAD_DIR):
        item_path = os.path.join(UPLOAD_DIR, item)
        try:
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.unlink(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path, ignore_errors=True)
        except Exception:
            pass

    # 2. Save all uploaded files
    for file in files:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

    # 3. Merge files and then trigger Re-indexing non-blockingly
    try:
        collect_all_files(UPLOAD_DIR, MERGED_FILE)
        result = await asyncio.to_thread(reindex_database)
        return {
            "status": result.get("status", "ok"),
            "message": result.get("message", f"Successfully processed {len(files)} files."),
            "is_cached": result.get("is_cached", False),
            "expires_at": result.get("expires_at", None)
        }
    except Exception as e:
        print(f"Error in process_multiple_files: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process files: {str(e)}")

@app.get("/search-files/")
async def search_files(query: str = Query(..., min_length=1)):
    """
    Endpoint 2: Searches for a string in the already merged file with accurate source tracking.
    """
    if not os.path.exists(MERGED_FILE) or os.path.getsize(MERGED_FILE) == 0:
        if os.path.exists(UPLOAD_DIR) and os.listdir(UPLOAD_DIR):
            collect_all_files(UPLOAD_DIR, MERGED_FILE)
        else:
            raise HTTPException(status_code=400, detail="No indexed files found. Please upload files first.")

    try:
        results = get_search_results_json(MERGED_FILE, query)
        return {"query": query, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ChatRequest(BaseModel):
    query: str

class AssistantChatRequest(BaseModel):
    query: str
    model: Optional[str] = "qwen3.5:0.8b"

@app.post("/assistant/chat")
async def assistant_chat_endpoint(request: AssistantChatRequest):
    try:
        response = ask_assistant(query=request.query, model=request.model or "qwen3.5:0.8b")
        return {
            "status": "ok",
            "answer": response["answer"],
            "model_used": response["model_used"]
        }
    except Exception as e:
        print(f"Assistant Chat Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/assistant/reindex")
async def assistant_reindex_endpoint():
    try:
        message = index_guide(force=True)
        return {"status": "ok", "message": message}
    except Exception as e:
        print(f"Assistant Reindex Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat-with-file/")
async def chat_with_file(request: ChatRequest):
    try:
        answer = await asyncio.to_thread(generate_answer, request.query)
        return {"answer": answer}
    except Exception as e:
        print(f"Chat Logic Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/summarize_bootlog/")
async def summarize():
    try:
        result = summarize_boot_log("uart_logs/uart_boot_log")
        return {
            "status": "ok",
            "data": result
        }
    except Exception as e:
        print(f"Chat Logic Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class AnalysisRequest(BaseModel):
    choice: int
    file_path: Optional[str] = None
    
@app.post("/get_analysis/")
async def analysis(request: Request):
    try:
        content_type = request.headers.get("content-type", "")
        choice_val = 1
        target_file_path = None

        backend_dir = Path(__file__).resolve().parent
        if "multipart/form-data" in content_type:
            form = await request.form()
            choice_val = int(form.get("choice", 1))
            uploaded_file = form.get("file")
            path_val = form.get("file_path")

            if uploaded_file and hasattr(uploaded_file, "filename") and uploaded_file.filename:
                EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
                saved_path = str(EXTRACTED_FILES_DIR / uploaded_file.filename)
                contents = await uploaded_file.read()
                with open(saved_path, "wb") as f:
                    f.write(contents)
                target_file_path = saved_path
            elif path_val:
                target_file_path = str(path_val).strip()
            else:
                raise HTTPException(status_code=400, detail="No file uploaded or file_path provided.")
        else:
            body = await request.json()
            choice_val = int(body.get("choice", 1))
            target_file_path = body.get("file_path")
            if not target_file_path:
                raise HTTPException(status_code=400, detail="file_path cannot be empty.")

        if not os.path.exists(target_file_path):
            alt_path = str(backend_dir / target_file_path)
            if os.path.exists(alt_path):
                target_file_path = alt_path
            elif (EXTRACTED_FILES_DIR / target_file_path).exists():
                target_file_path = str(EXTRACTED_FILES_DIR / target_file_path)
            else:
                raise HTTPException(status_code=404, detail=f"Target file '{target_file_path}' not found.")

        result = await asyncio.to_thread(run, choice_val, target_file_path)
        return {
            "status": "ok",
            "data": result
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error In get_analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class FlashRequest(BaseModel):
    spiSpeed: str
    chip: str
    fileName: str
    psuPower: bool
    piPower: bool


@app.post("/spi")
def extract_firmware(data: FlashRequest):
    EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
    extracted_dir = EXTRACTED_FILES_DIR

    raw_name = data.fileName.strip() if data.fileName else "firmware_dump.bin"
    base_name = os.path.basename(raw_name)
    if not base_name.endswith(".bin"):
        base_name += ".bin"
    output_path = str(extracted_dir / base_name)

    command = [
        "sudo",
        "flashrom",
        "-p",
        f"linux_spi:dev=/dev/spidev0.0,spispeed={data.spiSpeed}",
        "-c",
        data.chip,
        "-r",
        output_path,
    ]

    try:
        print(f"Starting the run to {output_path}")

        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

        print("Run complete")

        return {
            "success": True,
            "message": f"Firmware extracted successfully and saved as '{base_name}'.",
            "fileName": base_name,
            "saved_path": output_path
        }

    except subprocess.CalledProcessError as e:
        print("Error Occurred")
        msg = e.stdout.strip() if e.stdout else (e.stderr.strip() if e.stderr else str(e))
        return {
            "success": False,
            "returncode": e.returncode,
            "message": msg or "flashrom failed with non-zero exit status.",
            "stderr": e.stderr
        }
    except FileNotFoundError:
        return {
            "success": False,
            "message": "flashrom tool not found on system. Please install flashrom (sudo apt install flashrom) and ensure SPI is enabled."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Firmware extraction failed: {str(e)}"
        }

class ScanRequest(BaseModel):
    directory_path: Optional[str] = None
    max_file_size_mb: Optional[int] = 10

class CredentialItem(BaseModel):
    username: str
    credential: str
    hash_type: str
    source_file: str

class KeyCertItem(BaseModel):
    file: str
    type: str

class RotKeyItem(BaseModel):
    file: str
    context: str

class ScanResponse(BaseModel):
    status: str
    directory_scanned: str
    system_files: List[str]
    extracted_credentials: List[CredentialItem]
    keys_and_certificates: List[KeyCertItem]
    rotkeys_found: List[RotKeyItem]
    urls_and_domains: List[str]
    extraction_log: Optional[str] = None
    extraction_tool: Optional[str] = None
    

@app.post("/scan-credentials")
async def scan_firmware(request: Request):
    """
    Accepts target directory_path or an uploaded file (binary/archive/system file),
    executes firmware extraction (via Binwalk for binaries, tar/zip for archives)
    and deep secret/credential scanning, returning structured JSON results.
    """
    try:
        content_type = request.headers.get("content-type", "")
        max_size = 10
        scan_target = None
        extraction_log = None
        extraction_tool = None

        if "multipart/form-data" in content_type:
            form = await request.form()
            uploaded_file = form.get("file")
            dir_path = form.get("directory_path")
            max_size_raw = form.get("max_file_size_mb")
            if max_size_raw:
                try:
                    max_size = int(max_size_raw)
                except ValueError:
                    max_size = 10

            if uploaded_file and hasattr(uploaded_file, "filename") and uploaded_file.filename:
                EXTRACTED_FILES_DIR.mkdir(parents=True, exist_ok=True)
                saved_path = str(EXTRACTED_FILES_DIR / uploaded_file.filename)
                contents = await uploaded_file.read()
                with open(saved_path, "wb") as f:
                    f.write(contents)

                filename_lower = uploaded_file.filename.lower()
                # 1. ZIP Archive
                if filename_lower.endswith(".zip") and zipfile.is_zipfile(saved_path):
                    extract_dir = str(EXTRACTED_FILES_DIR / f"{Path(uploaded_file.filename).stem}_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with zipfile.ZipFile(saved_path, 'r') as zf:
                            zf.extractall(extract_dir)
                        scan_target = extract_dir
                        extraction_tool = "zip"
                        extraction_log = f"Successfully unpacked ZIP archive to:\n{extract_dir}"
                    except Exception as z_err:
                        print(f"[Warning] Zip extraction failed: {z_err}, scanning raw file instead.")
                        scan_target = saved_path
                        extraction_tool = "raw"
                        extraction_log = f"ZIP archive extraction failed: {z_err}"
                # 2. TAR Archive
                elif (filename_lower.endswith(".tar") or filename_lower.endswith(".tar.gz") or filename_lower.endswith(".tgz")) and tarfile.is_tarfile(saved_path):
                    extract_dir = str(EXTRACTED_FILES_DIR / f"{Path(uploaded_file.filename).stem}_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with tarfile.open(saved_path, 'r:*') as tf:
                            tf.extractall(extract_dir)
                        scan_target = extract_dir
                        extraction_tool = "tar"
                        extraction_log = f"Successfully unpacked TAR archive to:\n{extract_dir}"
                    except Exception as t_err:
                        print(f"[Warning] Tar extraction failed: {t_err}, scanning raw file instead.")
                        scan_target = saved_path
                        extraction_tool = "raw"
                        extraction_log = f"TAR archive extraction failed: {t_err}"
                # 3. Direct config/system files
                elif filename_lower in {'passwd', 'shadow', 'htpasswd', 'rototp.sh'} or filename_lower.endswith(('.conf', '.ini', '.txt', '.bak')):
                    scan_target = saved_path
                    extraction_tool = "direct_file"
                    extraction_log = f"Directly scanned configuration/system file: {uploaded_file.filename}"
                # 4. Firmware Binary or Image (.bin, .img, .rom, .elf, etc.): Run Binwalk!
                else:
                    extraction_tool = "binwalk"
                    extraction_log = ""
                    try:
                        cmd = ["binwalk", "-e", "--directory", str(EXTRACTED_FILES_DIR), saved_path]
                        binwalk_run = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                        extraction_log = binwalk_run.stdout or ""
                        if binwalk_run.stderr:
                            extraction_log += ("\n" if extraction_log else "") + binwalk_run.stderr
                    except subprocess.TimeoutExpired:
                        extraction_log = "Binwalk extraction timed out after 180 seconds."
                    except FileNotFoundError:
                        extraction_log = "Binwalk CLI tool is not installed on this system."
                    except Exception as b_err:
                        extraction_log = f"Binwalk extraction error: {str(b_err)}"

                    # Look for the generated extracted directory
                    expected_extracted_dir = EXTRACTED_FILES_DIR / f"_{uploaded_file.filename}.extracted"
                    matching_dirs = sorted(
                        EXTRACTED_FILES_DIR.glob(f"_{uploaded_file.filename}*.extracted"),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True
                    )

                    if expected_extracted_dir.exists() and any(expected_extracted_dir.iterdir()):
                        scan_target = str(expected_extracted_dir)
                    elif matching_dirs and any(matching_dirs[0].iterdir()):
                        scan_target = str(matching_dirs[0])
                    else:
                        scan_target = saved_path
                        if not extraction_log:
                            extraction_log = "No extractable filesystem partitions found by Binwalk. Scanned raw binary."
            elif dir_path:
                scan_target = str(dir_path).strip()
            else:
                raise HTTPException(status_code=400, detail="Please upload a file or provide a directory path.")
        else:
            # JSON request (backwards compatibility for FirmwareAnalysis component)
            body = await request.json()
            scan_target = body.get("directory_path", "").strip()
            max_size = body.get("max_file_size_mb") or 10
            if not scan_target:
                raise HTTPException(status_code=400, detail="directory_path cannot be empty.")

        # Path resolution for scan_target
        if not os.path.exists(scan_target):
            if (EXTRACTED_FILES_DIR / scan_target).exists():
                scan_target = str(EXTRACTED_FILES_DIR / scan_target)
            elif (PROJECT_ROOT / scan_target).exists():
                scan_target = str(PROJECT_ROOT / scan_target)
            elif (BACKEND_DIR / scan_target).exists():
                scan_target = str(BACKEND_DIR / scan_target)
            elif (BACKEND_DIR / "extracted_files" / scan_target).exists():
                scan_target = str(BACKEND_DIR / "extracted_files" / scan_target)
            elif (EXTRACTED_FILES_DIR / Path(scan_target).name).exists():
                scan_target = str(EXTRACTED_FILES_DIR / Path(scan_target).name)
            else:
                raise HTTPException(status_code=404, detail=f"Target path '{scan_target}' does not exist or is not reachable.")

        # Hardcoded_Password.py FirmwareScanner expects a directory.
        # If scan_target is an individual file (e.g. uploaded passwd/shadow/conf), isolate it into a dedicated folder.
        if os.path.isfile(scan_target):
            single_file_path = Path(scan_target).resolve()
            isolated_dir = EXTRACTED_FILES_DIR / f"_single_{single_file_path.stem}"
            isolated_dir.mkdir(parents=True, exist_ok=True)
            isolated_target = isolated_dir / single_file_path.name
            if not isolated_target.exists() or isolated_target.stat().st_mtime < single_file_path.stat().st_mtime:
                shutil.copy2(single_file_path, isolated_target)
            target_dir_to_scan = str(isolated_dir)
        else:
            target_dir_to_scan = scan_target

        # Initialize and execute backend scanner in worker thread using Hardcoded_Password.py
        scanner = FirmwareScanner(
            target_directory=target_dir_to_scan, 
            max_file_size_mb=max_size
        )
        scan_data = await asyncio.to_thread(scanner.run)

        # If a single file was scanned, restore original target path in response
        if os.path.isfile(scan_target):
            single_name = Path(scan_target).name
            scan_data["system_files"] = [
                scan_target if single_name in p else p
                for p in scan_data.get("system_files", [])
            ]
            for cred in scan_data.get("extracted_credentials", []):
                if single_name in cred.get("source_file", ""):
                    cred["source_file"] = scan_target
            for key in scan_data.get("keys_and_certificates", []):
                if single_name in key.get("file", ""):
                    key["file"] = scan_target
            for rot in scan_data.get("rotkeys_found", []):
                if single_name in rot.get("file", ""):
                    rot["file"] = scan_target

        return ScanResponse(
            status="success",
            directory_scanned=scan_target,
            extraction_log=extraction_log,
            extraction_tool=extraction_tool,
            system_files=scan_data["system_files"],
            extracted_credentials=scan_data["extracted_credentials"],
            keys_and_certificates=scan_data["keys_and_certificates"],
            rotkeys_found=scan_data["rotkeys_found"],
            urls_and_domains=scan_data["urls_and_domains"]
        )

    except HTTPException:
        raise
    except FileNotFoundError as fnf_err:
        raise HTTPException(status_code=404, detail=str(fnf_err))
    except Exception as e:
        print(f"Error in scan_firmware: {e}")
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")
        
class ChipRequest(BaseModel):
    spiSpeed: int


@app.post("/chipname")
def detect_chip_name(data: ChipRequest):

    command = [
        "sudo",
        "flashrom",
        "-p",
        f"linux_spi:dev=/dev/spidev0.0,spispeed={data.spiSpeed}",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

        output = result.stdout + result.stderr

        match = re.search(r'Found .* flash chip "([^"]+)"', output)

        if match:
            chip_name = match.group(1)

            return {
                "success": True,
                "chip": chip_name,
                "message": f"Detected chip: {chip_name}"
            }

        return {
            "success": False,
            "message": "Chip not detected"
        }

    except subprocess.CalledProcessError as e:

        output = (e.stdout or "") + (e.stderr or "")

        match = re.search(r'Found .* flash chip "([^"]+)"', output)

        if match:
            chip_name = match.group(1)

            return {
                "success": True,
                "chip": chip_name,
                "message": f"Detected chip: {chip_name}"
            }

        return {
            "success": False,
            "message": output.strip() or "flashrom exited with an error. Check SPI wiring and chip connection."
        }
    except FileNotFoundError:
        return {
            "success": False,
            "message": "flashrom tool not found on system. Please install flashrom (sudo apt install flashrom) and enable SPI."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Chip detection failed: {str(e)}"
        }

class BootlogScanPathRequest(BaseModel):
    target_path: str = Field(
        ..., 
        description="Absolute or relative path to a single bootlog file OR directory containing bootlogs.",
        example=os.getenv("BOOTLOGS_DIR", "../data/bootlogs")
    )
    cve_db_path: Optional[str] = Field(default=os.getenv("NVD_DB_DIR", "../data/nvd_db"))
    force_db_update: Optional[bool] = Field(default=False)


@app.post("/upload-bootlog")
async def upload_bootlog(file: UploadFile = File(...)):
    """
    Accepts an uploaded bootlog file, saves it into data/bootlogs,
    and returns its path for analysis.
    """
    try:
        bootlogs_dir = Path(__file__).resolve().parent.parent / "data" / "bootlogs"
        bootlogs_dir.mkdir(parents=True, exist_ok=True)

        safe_filename = Path(file.filename).name
        target_path = bootlogs_dir / safe_filename

        content = await file.read()
        with open(target_path, "wb") as f:
            f.write(content)

        relative_path = f"../data/bootlogs/{safe_filename}"
        return {
            "success": True,
            "filename": safe_filename,
            "path": relative_path,
            "absolute_path": str(target_path),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload bootlog: {str(e)}"
        )


@app.post("/scan-path", status_code=status.HTTP_200_OK)
def scan_path_endpoint(payload: BootlogScanPathRequest):
    if not payload.target_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target path cannot be empty."
        )

    try:
        scan_results = run_scan(
            target_path=payload.target_path,
            cve_db_path=payload.cve_db_path,
            force_db_update=payload.force_db_update
        )
        return {
            "success": True,
            "data": scan_results
        }
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing: {str(e)}"
        )


class BootlogContentRequest(BaseModel):
    boot_log: str
    filename: Optional[str] = "captured_bootlog.txt"
    force_db_update: Optional[bool] = False

@app.post("/scan-content", status_code=status.HTTP_200_OK)
def scan_content_endpoint(payload: BootlogContentRequest):
    if not payload.boot_log:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Boot log content cannot be empty."
        )
    try:
        scan_results = run_scan_content(
            boot_log_text=payload.boot_log,
            filename=payload.filename or "captured_bootlog.txt",
            force_db_update=payload.force_db_update or False
        )
        return {
            "success": True,
            "data": scan_results
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while scanning content: {str(e)}"
        )



class CveUpdateRequest(BaseModel):
    force: Optional[bool] = False

@app.get("/cve-database/status")
def cve_database_status():
    from cve_updater import get_database_status
    return get_database_status()

@app.post("/cve-database/update")
def cve_database_update(payload: Optional[CveUpdateRequest] = None):
    from cve_updater import trigger_database_update
    force = payload.force if payload else False
    return trigger_database_update(force=force)

@app.post("/cve-database/cancel")
def cve_database_cancel():
    from cve_updater import cancel_database_update
    return cancel_database_update()


def _compute_hashes_and_size(file_bytes: bytes):
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    crc32_val = f"{zlib.crc32(file_bytes) & 0xffffffff:08x}"
    size = len(file_bytes)

    if size < 1024:
        size_str = f"{size} B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.2f} KB"
    else:
        size_str = f"{size / (1024 * 1024):.2f} MB"

    return {
        "md5": md5,
        "sha256": sha256,
        "sha1": sha1,
        "crc32": crc32_val,
        "size_bytes": size,
        "size_formatted": size_str,
    }


@app.post("/compare-checksums")
async def compare_checksums_endpoint(
    file1: UploadFile = File(...),
    file2: UploadFile = File(...),
):
    try:
        content1 = await file1.read()
        content2 = await file2.read()

        info1 = _compute_hashes_and_size(content1)
        info1["filename"] = file1.filename or "file1.bin"

        info2 = _compute_hashes_and_size(content2)
        info2["filename"] = file2.filename or "file2.bin"

        is_same = (info1["sha256"] == info2["sha256"])

        return {
            "success": True,
            "is_same": is_same,
            "message": "Both files are same." if is_same else "Files are different (checksum mismatch).",
            "file1": info1,
            "file2": info2,
            "comparison": {
                "sha256_match": info1["sha256"] == info2["sha256"],
                "md5_match": info1["md5"] == info2["md5"],
                "sha1_match": info1["sha1"] == info2["sha1"],
                "crc32_match": info1["crc32"] == info2["crc32"],
                "size_match": info1["size_bytes"] == info2["size_bytes"],
            },
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate checksums: {str(e)}",
        )



