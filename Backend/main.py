from itertools import dropwhile
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, status, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import sys
import zipfile
import tarfile
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
from cv_scanner_40 import find_cve
from cv_scanner_40_new import find_cve1
from new_detect_baud import new_run_baud_detection
from Hardcoded_Password import FirmwareScanner
import time
import re
from scanner_wrapper import run_scan
#from cv_scanner_40 import find_cve

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
os.makedirs("extracted_files", exist_ok=True)
app.mount("/files", StaticFiles(directory="extracted_files"), name="files")


# ---------------- MODELS ---------------- #
class BootLog(BaseModel):
    boot_log: str


# ---------------- ROUTES ---------------- #

@app.get('/')
def home():
    return {"message": "hello"}


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), script: str = Form("binwalk"), firmAuditOption: str = Form(None), block_size: int = Form(None)):
    os.makedirs("extracted_files", exist_ok=True)
    filename = file.filename
    file_path = os.path.join("extracted_files", filename)

    # Save the uploaded file
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    try:
        firmaudit_script = os.path.join(os.path.dirname(__file__) or ".", "FirmAudit.py")

        if script == "binwalk":
            try:
                result = subprocess.run(
                    ["binwalk", "-e", "--directory", "extracted_files", file_path],
                    capture_output=True, text=True, check=True
                )
                return {"output": result.stdout}
            except FileNotFoundError:
                return {"error": "binwalk tool not found on this system. Please install binwalk or use FirmAudit."}

        elif script == "FirmAudit":
            if firmAuditOption == "-info":
                # Run FirmAudit.py with -info flag
                result = subprocess.run(
                    [sys.executable, firmaudit_script, file_path, "-info"],
                    capture_output=True, text=True, check=True
                )
                return {"output": result.stdout}
            elif firmAuditOption == "extract":
                # Run FirmAudit.py without -info flag (Extract and Analyze)
                result = subprocess.run(
                    [sys.executable, firmaudit_script, file_path],
                    capture_output=True, text=True, check=True
                )

                # The directory and testout file should be outside "extracted_files"
                base_name = os.path.splitext(filename)[0]
                extracted_dir = f"{base_name}_extracted"
                testout_file = f"{base_name}_testout.txt"

                # Check if the extracted directory exists
                extracted_dir_message = ""
                if os.path.exists(extracted_dir):
                    extracted_dir_message = f"Extracted files can be found in the {extracted_dir} directory located at {os.path.abspath(extracted_dir)}."
                else:
                    extracted_dir_message = "Error: Extracted directory not found. Please check if the extraction completed successfully."

                # Check if the testout file exists and display its content
                txt_output = ""
                if os.path.exists(testout_file):
                    with open(testout_file, "r", encoding="utf-8", errors="replace") as txt_file:
                        txt_output = txt_file.read()
                else:
                    txt_output = "Error: Testout file not found. Please ensure the script executed correctly and generated the necessary output."

                return {
                    "extracted_dir": extracted_dir,
                    "extracted_dir_message": extracted_dir_message,
                    "txt_output": txt_output
                }

        elif script == "entropy":
            # Run entropy via FirmAudit.py
            result = subprocess.run(
                [sys.executable, firmaudit_script, file_path, "-E"],
                capture_output=True, text=True, check=True
            )

            base_name = os.path.splitext(filename)[0]
            txt_output_path = f"{base_name}_entropy.txt"
            html_output_path = f"{base_name}_entropy.html"

            if os.path.exists(txt_output_path) and os.path.exists(html_output_path):
                with open(txt_output_path, "r", encoding="utf-8", errors="replace") as txt_file:
                    txt_content = txt_file.read()
                with open(html_output_path, "r", encoding="utf-8", errors="replace") as html_file:
                    html_content = html_file.read()
                return {
                    "txt_output": txt_content,
                    "html_output": html_content
                }
            else:
                return {"error": "Entropy output files not generated."}

        elif script == "extractor":
            # Run FirmAudit.py with block size
            cmd = [sys.executable, firmaudit_script, file_path]
            if block_size is not None:
                cmd.extend(["-B", str(block_size)])
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            base_name = os.path.splitext(filename)[0]
            txt_output_path = f"{base_name}_entropy.txt"
            html_output_path = f"{base_name}_entropy.html"

            if os.path.exists(txt_output_path) and os.path.exists(html_output_path):
                with open(txt_output_path, "r", encoding="utf-8", errors="replace") as txt_file:
                    txt_content = txt_file.read()
                with open(html_output_path, "r", encoding="utf-8", errors="replace") as html_file:
                    html_content = html_file.read()
                return {
                    "txt_output": txt_content,
                    "html_output": html_content
                }
            else:
                return {"output": result.stdout or "Extractor completed."}

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
    
@app.get("/switch_power/{flag}")
async def switch_power(flag: int):
    try:
        if flag == 0:
            power_thread.set_state(0)
            msg = "Power set to state 0 (OFF)"
        else:
            power_thread.set_state(1)
            msg = "Power set to state 1 (ON)"
        return {"status": "ok", "message": msg, "flag": flag}
    except Exception as e:
        return {"status": "error", "message": f"Failed to toggle power: {str(e)}"}

@app.get("/new_switch_power/{flag}")
async def new_switch_power(flag: int):
    try:
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(OCTOCOUPLER_POWER_PIN, GPIO.OUT)

        if flag == 0:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.HIGH)
            msg = "Octocoupler power set to HIGH (OFF)"
        else:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.LOW)
            msg = "Octocoupler power set to LOW (ON)"

        return {"status": "ok", "message": msg, "flag": flag}
    except Exception as e:
        return {"status": "error", "message": f"Failed to switch octocoupler power: {str(e)}"}

@app.get("/hardware/info")
async def hardware_info():
    """Returns system architecture diagnostics and pin mapping for Raspberry Pi 5."""
    return get_hardware_diagnostics()

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
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.HIGH)
            time.sleep(pon_sec)
            if _glitch_stop_flag.is_set():
                break
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.LOW)
            time.sleep(poff_sec)
    except Exception as e:
        print(f"[ERROR] Octocoupler glitch loop exception: {e}")
    finally:
        try:
            GPIO.output(OCTOCOUPLER_POWER_PIN, GPIO.HIGH)
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

@app.get("/set_channel/{channel}")
async def set_channel(channel: int):
    try:
        power_thread.set_channel(channel)
        return {"status": "ok", "message": f"Channel set to {channel}"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to set channel: {str(e)}"}

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
async def uart_console(baud: int = 115200):
    try:
        res = check_uart_console.main(baud, power_thread)
        return res
    except Exception as e:
        return {
            "success": False,
            "is_available": False,
            "status": "error",
            "data": f"Error: {str(e)}",
            "message": str(e),
            "log": str(e)
        }

@app.post("/cv_scan/")
async def cv_scan(boot_log: BootLog):
    output = find_cve(boot_log.boot_log)
    return {"data": output or "Analysis Done"}


@app.get("/list-files/")
async def list_files():
    backend_dir = Path(__file__).resolve().parent
    extracted_dir = backend_dir / "extracted_files"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    return os.listdir(str(extracted_dir))


FIRM_DIR = os.getenv("FIRM_DIR", str(Path(__file__).resolve().parent / "extracted_files"))

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
        
        output = find_cve1(temp)
        
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
                extracted_dir = backend_dir / "extracted_files"
                extracted_dir.mkdir(parents=True, exist_ok=True)
                saved_path = str(extracted_dir / uploaded_file.filename)
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
    command = [
        "sudo",
        "flashrom",
        "-p",
        f"linux_spi:dev=/dev/spidev0.0,spispeed={data.spiSpeed}",
        "-c",
        data.chip,
        "-r",
        data.fileName,
    ]

    try:
        print("Starting the run")

        subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

        print("Run complete")

        return {
            "success": True,
            "message": f"Firmware extracted successfully and saved as '{data.fileName}'."
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
    

@app.post("/scan-credentials")
async def scan_firmware(request: Request):
    """
    Accepts target directory_path or an uploaded file (binary/archive/system file),
    executes firmware scan, and returns scan details in structured JSON format.
    """
    try:
        content_type = request.headers.get("content-type", "")
        max_size = 10
        scan_target = None

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

            backend_dir = Path(__file__).resolve().parent
            if uploaded_file and hasattr(uploaded_file, "filename") and uploaded_file.filename:
                extracted_dir = backend_dir / "extracted_files"
                extracted_dir.mkdir(parents=True, exist_ok=True)
                saved_path = str(extracted_dir / uploaded_file.filename)
                contents = await uploaded_file.read()
                with open(saved_path, "wb") as f:
                    f.write(contents)

                filename_lower = uploaded_file.filename.lower()
                # If uploaded file is a ZIP archive, unpack and scan directory
                if filename_lower.endswith(".zip") and zipfile.is_zipfile(saved_path):
                    extract_dir = str(extracted_dir / f"{Path(uploaded_file.filename).stem}_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with zipfile.ZipFile(saved_path, 'r') as zf:
                            zf.extractall(extract_dir)
                        scan_target = extract_dir
                    except Exception as z_err:
                        print(f"[Warning] Zip extraction failed: {z_err}, scanning raw file instead.")
                        scan_target = saved_path
                # If uploaded file is a TAR archive, unpack and scan directory
                elif (filename_lower.endswith(".tar") or filename_lower.endswith(".tar.gz") or filename_lower.endswith(".tgz")) and tarfile.is_tarfile(saved_path):
                    extract_dir = str(extracted_dir / f"{Path(uploaded_file.filename).stem}_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    try:
                        with tarfile.open(saved_path, 'r:*') as tf:
                            tf.extractall(extract_dir)
                        scan_target = extract_dir
                    except Exception as t_err:
                        print(f"[Warning] Tar extraction failed: {t_err}, scanning raw file instead.")
                        scan_target = saved_path
                else:
                    scan_target = saved_path
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

        backend_dir = Path(__file__).resolve().parent
        if not os.path.exists(scan_target):
            if (backend_dir / scan_target).exists():
                scan_target = str(backend_dir / scan_target)
            elif (backend_dir.parent / scan_target).exists():
                scan_target = str(backend_dir.parent / scan_target)
            elif (backend_dir / "extracted_files" / scan_target).exists():
                scan_target = str(backend_dir / "extracted_files" / scan_target)
            else:
                raise HTTPException(status_code=404, detail=f"Target path '{scan_target}' does not exist or is not reachable.")

        # Initialize and execute backend scanner in worker thread
        scanner = FirmwareScanner(
            target_directory=scan_target, 
            max_file_size_mb=max_size
        )
        scan_data = await asyncio.to_thread(scanner.run)

        return ScanResponse(
            status="success",
            directory_scanned=scan_target,
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

