from itertools import dropwhile
from fastapi import FastAPI, UploadFile, File, Form,HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import RPi.GPIO as GPIO
from time import sleep
import threading
import os
import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from bruteforce_uart import check_login
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
import subprocess
import httpx
import asyncio
from typing import Optional
from EPSS_CVSS_Extract import get_cached_vulnerabilities
from collect_files import collect_all_files, get_search_results_json
from typing import List
import shutil
from ChatBot import generate_answer,reindex_database
from BootLog_Summary import summarize_boot_log
from Agent_Analyze import run

switching_pin = 19
volt_pin = 20
relay_pin = 21


GPIO.setmode(GPIO.BCM) 
GPIO.setup(volt_pin, GPIO.OUT)
FIRM_DIR = "extracted_firm"
#LOG_DIR = "uart_logs"
LOG_DIR = "/home/hardware-security/Downloads/backend/uart_logs"
GPIO.setup(relay_pin, GPIO.OUT)
GPIO.output(relay_pin, GPIO.HIGH)
power_thread = PowerMod(channel_pin=26, switching_pin=6)
power_thread.start()
import os
os.makedirs("uart_logs", exist_ok=True)
app = FastAPI()


origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#Ensure the dir exists
os.makedirs("extracted_files", exist_ok=True)

#mount the static files dir
app.mount("/files", StaticFiles(directory="extracted_files"), name="files")


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), script: str = Form("binwalk"), firmAuditOption: str = Form(None), block_size: int = Form(None)):
    filename = file.filename
    file_path = os.path.join("extracted_files", filename)

    # Save the uploaded file
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)

    try:
        if script == "binwalk":
            result = subprocess.run(
                ["binwalk", "-e", "--directory", "extracted_files", file_path],
                capture_output=True, text=True, check=True
            )
            return {"output": result.stdout}

        elif script == "FirmAudit":
            if firmAuditOption == "-info":
                # Run FirmAudit.py with -info flag
                result = subprocess.run(
                    ["python3", "FirmAudit.py", file_path, "-info"],
                    capture_output=True, text=True, check=True
                )
                return {"output": result.stdout}
            elif firmAuditOption == "extract":
                # Run FirmAudit.py without -info flag (Extract and Analyze)
                result = subprocess.run(
                    ["python3", "FirmAudit.py", file_path],
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
                    with open(testout_file, "r") as txt_file:
                        txt_output = txt_file.read()
                else:
                    txt_output = "Error: Testout file not found. Please ensure the script executed correctly and generated the necessary output."

                return {
                    "extracted_dir_message": extracted_dir_message,
                    "txt_output": txt_output
                }
        
        elif script == "entropy":
            # Run entropy.py script
            result = subprocess.run(
                ["python3", "FirmAudit.py", file_path, "-E"],
                capture_output=True, text=True, check=True
            )
            
            # Extract filename (without extension)
            base_name = os.path.splitext(filename)[0]
            
            # Output files are named as base_name_entropy.txt and base_name_entropy.html
            txt_output_path = f"{base_name}_entropy.txt"
            html_output_path = f"{base_name}_entropy.html"
            
            # Read contents of the generated files
            if os.path.exists(txt_output_path) and os.path.exists(html_output_path):
                with open(txt_output_path, "r") as txt_file:
                    txt_content = txt_file.read()
                with open(html_output_path, "r") as html_file:
                    html_content = html_file.read()
                return {
                    "txt_output": txt_content,
                    "html_output": html_content
                }
            else:
                return {"error": "Output files not found."}
        
        elif script == "extractor":
            # Run FirmAudit.py with block size
            result = subprocess.run(
                ["python3", "FirmAudit.py", file_path, "-B", str(block_size)],
                capture_output=True, text=True, check=True
            )
            
            # Extract filename (without extension)
            base_name = os.path.splitext(filename)[0]
            
            # Output files are named as base_name_entropy.txt and base_name_entropy.html
            txt_output_path = f"{base_name}_entropy.txt"
            html_output_path = f"{base_name}_entropy.html"
            
            # Read contents of the generated files
            if os.path.exists(txt_output_path) and os.path.exists(html_output_path):
                with open(txt_output_path, "r") as txt_file:
                    txt_content = txt_file.read()
                with open(html_output_path, "r") as html_file:
                    html_content = html_file.read()
                return {
                    "txt_output": txt_content,
                    "html_output": html_content
                }
            else:
                return {"error": "Output files not found."}

        else:
            return {"error": "Invalid script selected."}

    except subprocess.CalledProcessError as e:
        # Log the error if the command fails
        print(f"Error running {script}: {e.stderr}")
        return {"error": e.stderr}


@app.get("/list-files/")
async def list_files():
    files = os.listdir("extracted_files")
    return JSONResponse(content=files)
    
@app.get("/list-all-files/")
async def list_all_files():
    try:
        # Get the list of all files and folders in the current directory
        files_and_folders = os.listdir(".")  # List all files and folders in the current directory
        return JSONResponse(content=files_and_folders)
    except Exception as e:
        # Log the error and return a proper error message
        return JSONResponse(content={"error": str(e)}, status_code=500)


class BootLog(BaseModel):
    boot_log: str


@app.get('/')
def getHome():
    print('Hello world')
    content = {'message': 'hello'}
    headers={'Access-Control-Allow-Origin':'*',
             'Access-Control-Allow-Origin':'GET, POST, PUT, DELETE, OPTIONS',
             'Access-Control-Allow-Headers':'Content-Type, Authorization'}
    return JSONResponse(content=content, headers=headers)


@app.get("/set_volt/{freq}")
async def volt_glitch(freq):
    print(freq)
    power_thread.unset_state()
    power_thread.set_delay(int(freq))
    return {"data":"OK"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon,poff):
    print('pon : ',pon)
    print('poff ; ' ,poff)
    power_thread.unset_state()
    print(f"setting on {pon} poff {poff}")
    power_thread.set_poweroff(int(poff))
    power_thread.set_poweron(int(pon))
    return {"data":"OK _pon"}

@app.get("/set_channel/{channel}")
async def volt_glitch_channel(channel):
    power_thread.set_channel(int(channel))
    return {"data":"OK Channel set"}

@app.get("/switch_power/{flg}")
async def switch_power(flg):
    if flg == "0":
        print("set of ")
        power_thread.set_state(0)

    else:
        print("set on")
        power_thread.set_state(1)
        #power_thread.set_poweron(10000)
     #power_thread.set_channel(int(channel))
    return {"data":"OF q"}

@app.get("/check_uart_console/{baud}")
async def uart_console(baud = 115200):
    print('uart_console')
    check = await check_uart_console.main(baud)
    if check:
        return {"data":"Console Found"}
    return {"data":"No Console Found"}
    
@app.get("/boot_log_analyse/{file_name}")
async def boot_log(file_name = None):
    if file_name is not None:
        check_default_key.output_file = "uart_logs/"+file_name
    imp = await check_default_key.main()
    imp_output = "\n".join(imp)
    # output=""
    # with open("uart_logs/"+file_name, "r") as f:
    #     for i in f:
    #         output+=i
    return {"data":imp_output}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def cap_boot(sampling_rate,power_cycle,baud_rate):
    print(sampling_rate,power_cycle,baud_rate)
    output=""
    capture_uart_boot.main(baud_rate, sampling_rate, power_cycle, power_thread)
    with open(capture_uart_boot.output_file, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/show_raw_boot_logs/{log_name}")
async def cap_boot_show(log_name = None):
    output=""
    log_name = "uart_boot_log"
    if log_name is None:
        log_name = "uart_boot_log"
    with open("uart_logs/"+log_name, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate,power_cycle_delay):
    print(sampling_rate, power_cycle_delay, "baud detect")
    detect_baud.main(sampling_rate, power_cycle_delay, power_thread)
    bauds = ""
    
    with open(detect_baud.output_file, "r") as f:
        for i in f:
            bauds+=i
    print("_______________________________________")
    print(bauds)
    return {"dtt": bauds}

@app.post("/cv_scan/")
async def cv_scan(boot_log : BootLog):
    output = find_cve(boot_log.boot_log)
    print(boot_log.boot_log)
    print('output : ',output)
    if output == '':
        output = 'Analysis Done'
    return {'data' : output}


@app.get("/list_devices/{speed}")
async def list_devices(speed:str = '4096'):
    list_output = await helper.list_device_call(speed)
    return {"data": list_output}


@app.get("/download_firm/{filename}")
def down_firm(filename: str = "test"):
    fname = filename
    print("downloading "+fname)
    return FileResponse(FIRM_DIR+"/"+fname+".bin")



@app.get("/dump_firm/{filename}")
def dump_firm(filename:str = 'test'):
    firm_name = filename
    return {"data":helper.dump_firm_call("8000", firm_name+".bin", FIRM_DIR)}




@app.get("/get_strings/{file_name}")
def analyse_firm(file_name):
    filename = file_name
    return {"data" :{"invoked_data":"none", "data": "\n".join(helper.get_strings(FIRM_DIR+"/"+filename))}}
    
@app.get("/get_binwalk/{file_name}")
def analyse_firm_binwalk(file_name):
    filename = file_name
    output = helper.binwalk_des(FIRM_DIR+"/"+filename)
    print(output)
    return {"data": output}


@app.post("/uploadfile/")
async def upload_file(file: UploadFile, baud_rate):
    # Get the file's contents
    file_contents = await file.read()
    print(file_contents)
    # Process the file content (e.g., save it to a file or perform some operation)
    with open(f"uploads/{file.filename}", "wb") as f:
        f.write(file_contents)

    fail_key = "Invalid Password"
    with open(f"uploads/{file.filename}", "r") as f:
        for cred in f:
            print("checking ", cred)
            if check_login(baud_rate, fail_key, cred):
                print("working ", cred)
                return {"data" : cred}
            else:
                print(cred, "Not working")
    
    return {"data" : "No Credentials match"}

@app.get("/cves")
async def cves_endpoint():
    """
    Returns JSON: { "vulnerabilities": [ { id, baseScore, epssScore, epssPercentile, epssError } ] }
    """
    input_file = "output1.txt"
    try:
        data = get_cached_vulnerabilities(input_file)
    except Exception as e:
        # Catch unexpected errors from the imported function and return 500
        raise HTTPException(status_code=500, detail=f"Failed to compute vulnerabilities: {e}")
    return JSONResponse({"vulnerabilities": data})

UPLOAD_DIR = "uploads"
MERGED_FILE = "combined_files_output.txt"

@app.post("/process-files/")
async def process_multiple_files(files: list[UploadFile] = File(...)):
    # 1. Clear/Create the upload directory
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR)

    # 2. Save all uploaded files
    for file in files:
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

    # 3. Merge files and then trigger Re-indexing
    try:
        collect_all_files(UPLOAD_DIR, MERGED_FILE) # Your existing logic
        reindex_database() # <--- THIS IS THE KEY ADDITION
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process files: {e}")

    return {"message": f"Successfully merged {len(files)} files and updated the database."}

@app.get("/search-files/")
async def search_files(query: str = Query(..., min_length=1)):
    """
    Endpoint 2: Searches for a string in the already merged file.
    """
    if not os.path.exists(MERGED_FILE):
        raise HTTPException(status_code=400, detail="No merged file found. Please upload files first.")

    try:
        # Note: We need to modify your search_in_output to RETURN data 
        # instead of just printing it. See below for the modification.
        results = get_search_results_json(MERGED_FILE, query)
        return {"query": query, "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ChatRequest(BaseModel):
    query: str
    
@app.post("/chat-with-file/")
async def chat_with_file(request: ChatRequest):
    try:
        # Access the query from the request object
        # In v1, we use request.query
        answer = generate_answer(request.query)
        
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
    file_path: str
    
@app.post("/get_analysis/")
async def analysis(request:AnalysisRequest):
	try:
		result = await run(request.choice,request.file_path)
		return {
			"status" : "ok",
			"data" : result
		}
	except Exception as e:
		print(f"Error In the code: {e}")
		raise HTTPException(status_code=500,detail=str(e))























"""
from itertools import dropwhile
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import RPi.GPIO as GPIO
from time import sleep
import threading
import os
import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from bruteforce_uart import check_login
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
import subprocess



switching_pin = 19
volt_pin = 20
relay_pin = 21


GPIO.setmode(GPIO.BCM) 
GPIO.setup(volt_pin, GPIO.OUT)
FIRM_DIR = "extracted_firm"
LOG_DIR = "uart_logs"
GPIO.setup(relay_pin, GPIO.OUT)
GPIO.output(relay_pin, GPIO.HIGH)
power_thread = PowerMod(channel_pin=26, switching_pin=6)
power_thread.start()

app = FastAPI()


origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


os.makedirs("extracted_files", exist_ok=True)

app.mount("/files", StaticFiles(directory="extracted_files"), name="files")

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    filename = file.filename
    file_path = os.path.join("extracted_files", filename)
    
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)
    
    output_dir = "extracted_files"
    result = subprocess.run(["binwalk", "-e", "--directory", output_dir, file_path], capture_output=True, text=True)
    print(result.stdout)  # Print the output to the terminal
    return {"output": result.stdout}

@app.get("/list-files/")
async def list_files():
    files = os.listdir("extracted_files")
    return JSONResponse(content=files)


class BootLog(BaseModel):
    boot_log: str


@app.get('/')
def getHome():
    print('Hello world')
    content = {'message': 'hello'}
    headers={'Access-Control-Allow-Origin':'*',
             'Access-Control-Allow-Origin':'GET, POST, PUT, DELETE, OPTIONS',
             'Access-Control-Allow-Headers':'Content-Type, Authorization'}
    return JSONResponse(content=content, headers=headers)


@app.get("/set_volt/{freq}")
async def volt_glitch(freq):
    print(freq)
    power_thread.unset_state()
    power_thread.set_delay(int(freq))
    return {"data":"OK"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon,poff):
    print('pon : ',pon)
    print('poff ; ' ,poff)
    power_thread.unset_state()
    print(f"setting on {pon} poff {poff}")
    power_thread.set_poweroff(int(poff))
    power_thread.set_poweron(int(pon))
    return {"data":"OK _pon"}

@app.get("/set_channel/{channel}")
async def volt_glitch_channel(channel):
    power_thread.set_channel(int(channel))
    return {"data":"OK Channel set"}

@app.get("/switch_power/{flg}")
async def switch_power(flg):
    if flg == "0":
        print("set of ")
        power_thread.set_state(0)

    else:
        print("set on")
        power_thread.set_state(1)
        #power_thread.set_poweron(10000)
     #power_thread.set_channel(int(channel))
    return {"data":"OF q"}

@app.get("/check_uart_console/{baud}")
async def uart_console(baud = 115200):
    print('uart_console')
    check = await check_uart_console.main(baud)
    if check:
        return {"data":"Console Found"}
    return {"data":"No Console Found"}
    
@app.get("/boot_log_analyse/{file_name}")
async def boot_log(file_name = None):
    if file_name is not None:
        check_default_key.output_file = "uart_logs/"+file_name
    imp = await check_default_key.main()
    imp_output = "\n".join(imp)
    # output=""
    # with open("uart_logs/"+file_name, "r") as f:
    #     for i in f:
    #         output+=i
    return {"data":imp_output}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def cap_boot(sampling_rate,power_cycle,baud_rate):
    print(sampling_rate,power_cycle,baud_rate)
    output=""
    capture_uart_boot.main(baud_rate, sampling_rate, power_cycle, power_thread)
    with open(capture_uart_boot.output_file, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/show_raw_boot_logs/{log_name}")
async def cap_boot_show(log_name = None):
    output=""
    if log_name is None:
        log_name = "uart_boot_log"
    with open("uart_logs/"+log_name, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate,power_cycle_delay):
    print(sampling_rate, power_cycle_delay, "baud detect")
    detect_baud.main(sampling_rate, power_cycle_delay, power_thread)
    bauds = ""
    
    with open(detect_baud.output_file, "r") as f:
        for i in f:
            bauds+=i
    print("_______________________________________")
    print(bauds)
    return {"dtt": bauds}

@app.post("/cv_scan/")
async def cv_scan(boot_log : BootLog):
    output = find_cve(boot_log.boot_log)
    print(boot_log.boot_log)
    print('output : ',output)
    if output == '':
        output = 'Analysis Done'
    return {'data' : output}


@app.get("/list_devices/{speed}")
async def list_devices(speed:str = '4096'):
    list_output = await helper.list_device_call(speed)
    return {"data": list_output}


@app.get("/download_firm/{filename}")
def down_firm(filename: str = "test"):
    fname = filename
    print("downloading "+fname)
    return FileResponse(FIRM_DIR+"/"+fname+".bin")



@app.get("/dump_firm/{filename}")
def dump_firm(filename:str = 'test'):
    firm_name = filename
    return {"data":helper.dump_firm_call("8000", firm_name+".bin", FIRM_DIR)}




@app.get("/get_strings/{file_name}")
def analyse_firm(file_name):
    filename = file_name
    return {"data" :{"invoked_data":"none", "data": "\n".join(helper.get_strings(FIRM_DIR+"/"+filename))}}
    
@app.get("/get_binwalk/{file_name}")
def analyse_firm_binwalk(file_name):
    filename = file_name
    output = helper.binwalk_des(FIRM_DIR+"/"+filename)
    print(output)
    return {"data": output}


@app.post("/uploadfile/")
async def upload_file(file: UploadFile, baud_rate):
    # Get the file's contents
    file_contents = await file.read()
    print(file_contents)
    # Process the file content (e.g., save it to a file or perform some operation)
    with open(f"uploads/{file.filename}", "wb") as f:
        f.write(file_contents)

    fail_key = "Invalid Password"
    with open(f"uploads/{file.filename}", "r") as f:
        for cred in f:
            print("checking ", cred)
            if check_login(baud_rate, fail_key, cred):
                print("working ", cred)
                return {"data" : cred}
            else:
                print(cred, "Not working")
    
    return {"data" : "No Credentials match"}
"""
























"""
from itertools import dropwhile
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import RPi.GPIO as GPIO
from time import sleep
import threading
import os
import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from bruteforce_uart import check_login
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
import subprocess



switching_pin = 19
volt_pin = 20
relay_pin = 21


GPIO.setmode(GPIO.BCM) 
GPIO.setup(volt_pin, GPIO.OUT)
FIRM_DIR = "extracted_firm"
LOG_DIR = "uart_logs"
GPIO.setup(relay_pin, GPIO.OUT)
GPIO.output(relay_pin, GPIO.HIGH)
power_thread = PowerMod(channel_pin=26, switching_pin=6)
power_thread.start()

app = FastAPI()


origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


os.makedirs("extracted_files", exist_ok=True)

app.mount("/files", StaticFiles(directory="extracted_files"), name="files")


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    filename = file.filename
    file_path = os.path.join(FIRM_DIR, filename)
    
    contents = await file.read()
    with open(file_path, "wb") as f:
        f.write(contents)
    
    # Run the binwalk command
    result = subprocess.run(["binwalk", "-e", file_path], capture_output=True, text=True)
    return JSONResponse(content={"output": result.stdout})

@app.get("/list-files/")
async def list_files():
    files = os.listdir("extracted_files")
    return JSONResponse(content=files)


class BootLog(BaseModel):
    boot_log: str


@app.get('/')
def getHome():
    print('Hello world')
    content = {'message': 'hello'}
    headers={'Access-Control-Allow-Origin':'*',
             'Access-Control-Allow-Origin':'GET, POST, PUT, DELETE, OPTIONS',
             'Access-Control-Allow-Headers':'Content-Type, Authorization'}
    return JSONResponse(content=content, headers=headers)


@app.get("/set_volt/{freq}")
async def volt_glitch(freq):
    print(freq)
    power_thread.unset_state()
    power_thread.set_delay(int(freq))
    return {"data":"OK"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon,poff):
    print('pon : ',pon)
    print('poff ; ' ,poff)
    power_thread.unset_state()
    print(f"setting on {pon} poff {poff}")
    power_thread.set_poweroff(int(poff))
    power_thread.set_poweron(int(pon))
    return {"data":"OK _pon"}

@app.get("/set_channel/{channel}")
async def volt_glitch_channel(channel):
    power_thread.set_channel(int(channel))
    return {"data":"OK Channel set"}

@app.get("/switch_power/{flg}")
async def switch_power(flg):
    if flg == "0":
        print("set of ")
        power_thread.set_state(0)

    else:
        print("set on")
        power_thread.set_state(1)
        #power_thread.set_poweron(10000)
     #power_thread.set_channel(int(channel))
    return {"data":"OF q"}

@app.get("/check_uart_console/{baud}")
async def uart_console(baud = 115200):
    print('uart_console')
    check = await check_uart_console.main(baud)
    if check:
        return {"data":"Console Found"}
    return {"data":"No Console Found"}
    
@app.get("/boot_log_analyse/{file_name}")
async def boot_log(file_name = None):
    if file_name is not None:
        check_default_key.output_file = "uart_logs/"+file_name
    imp = await check_default_key.main()
    imp_output = "\n".join(imp)
    # output=""
    # with open("uart_logs/"+file_name, "r") as f:
    #     for i in f:
    #         output+=i
    return {"data":imp_output}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def cap_boot(sampling_rate,power_cycle,baud_rate):
    print(sampling_rate,power_cycle,baud_rate)
    output=""
    capture_uart_boot.main(baud_rate, sampling_rate, power_cycle, power_thread)
    with open(capture_uart_boot.output_file, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/show_raw_boot_logs/{log_name}")
async def cap_boot_show(log_name = None):
    output=""
    if log_name is None:
        log_name = "uart_boot_log"
    with open("uart_logs/"+log_name, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate,power_cycle_delay):
    print(sampling_rate, power_cycle_delay, "baud detect")
    detect_baud.main(sampling_rate, power_cycle_delay, power_thread)
    bauds = ""
    
    with open(detect_baud.output_file, "r") as f:
        for i in f:
            bauds+=i
    print("_______________________________________")
    print(bauds)
    return {"dtt": bauds}

@app.post("/cv_scan/")
async def cv_scan(boot_log : BootLog):
    output = find_cve(boot_log.boot_log)
    print(boot_log.boot_log)
    print('output : ',output)
    if output == '':
        output = 'Analysis Done'
    return {'data' : output}


@app.get("/list_devices/{speed}")
async def list_devices(speed:str = '4096'):
    list_output = await helper.list_device_call(speed)
    return {"data": list_output}


@app.get("/download_firm/{filename}")
def down_firm(filename: str = "test"):
    fname = filename
    print("downloading "+fname)
    return FileResponse(FIRM_DIR+"/"+fname+".bin")



@app.get("/dump_firm/{filename}")
def dump_firm(filename:str = 'test'):
    firm_name = filename
    return {"data":helper.dump_firm_call("8000", firm_name+".bin", FIRM_DIR)}




@app.get("/get_strings/{file_name}")
def analyse_firm(file_name):
    filename = file_name
    return {"data" :{"invoked_data":"none", "data": "\n".join(helper.get_strings(FIRM_DIR+"/"+filename))}}
    
@app.get("/get_binwalk/{file_name}")
def analyse_firm_binwalk(file_name):
    filename = file_name
    output = helper.binwalk_des(FIRM_DIR+"/"+filename)
    print(output)
    return {"data": output}


@app.post("/uploadfile/")
async def upload_file(file: UploadFile, baud_rate):
    # Get the file's contents
    file_contents = await file.read()
    print(file_contents)
    # Process the file content (e.g., save it to a file or perform some operation)
    with open(f"uploads/{file.filename}", "wb") as f:
        f.write(file_contents)

    fail_key = "Invalid Password"
    with open(f"uploads/{file.filename}", "r") as f:
        for cred in f:
            print("checking ", cred)
            if check_login(baud_rate, fail_key, cred):
                print("working ", cred)
                return {"data" : cred}
            else:
                print(cred, "Not working")
    
    return {"data" : "No Credentials match"}

"""























"""
from itertools import dropwhile
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import RPi.GPIO as GPIO
from time import sleep
import threading
import os
import helper
import detect_baud, check_uart_console, check_default_key, capture_uart_boot
from cv_scanner import find_cve
from power_module import PowerMod
from bruteforce_uart import check_login
from pydantic import BaseModel

switching_pin = 19
volt_pin = 20
relay_pin = 21


GPIO.setmode(GPIO.BCM) 
GPIO.setup(volt_pin, GPIO.OUT)
FIRM_DIR = "extracted_firm"
LOG_DIR = "uart_logs"
GPIO.setup(relay_pin, GPIO.OUT)
GPIO.output(relay_pin, GPIO.HIGH)
power_thread = PowerMod(channel_pin=26, switching_pin=6)
power_thread.start()

app = FastAPI()


origins = [
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BootLog(BaseModel):
    boot_log: str


@app.get('/')
def getHome():
    print('Hello world')
    content = {'message': 'hello'}
    headers={'Access-Control-Allow-Origin':'*',
             'Access-Control-Allow-Origin':'GET, POST, PUT, DELETE, OPTIONS',
             'Access-Control-Allow-Headers':'Content-Type, Authorization'}
    return JSONResponse(content=content, headers=headers)


@app.get("/set_volt/{freq}")
async def volt_glitch(freq):
    print(freq)
    power_thread.unset_state()
    power_thread.set_delay(int(freq))
    return {"data":"OK"}

@app.get("/set_volt_custom/{pon}/{poff}")
async def volt_glitch_custom(pon,poff):
    print('pon : ',pon)
    print('poff ; ' ,poff)
    power_thread.unset_state()
    print(f"setting on {pon} poff {poff}")
    power_thread.set_poweroff(int(poff))
    power_thread.set_poweron(int(pon))
    return {"data":"OK _pon"}

@app.get("/set_channel/{channel}")
async def volt_glitch_channel(channel):
    power_thread.set_channel(int(channel))
    return {"data":"OK Channel set"}

@app.get("/switch_power/{flg}")
async def switch_power(flg):
    if flg == "0":
        print("set of ")
        power_thread.set_state(0)

    else:
        print("set on")
        power_thread.set_state(1)
        #power_thread.set_poweron(10000)
     #power_thread.set_channel(int(channel))
    return {"data":"OF q"}

@app.get("/check_uart_console/{baud}")
async def uart_console(baud = 115200):
    print('uart_console')
    check = await check_uart_console.main(baud)
    if check:
        return {"data":"Console Found"}
    return {"data":"No Console Found"}
    
@app.get("/boot_log_analyse/{file_name}")
async def boot_log(file_name = None):
    if file_name is not None:
        check_default_key.output_file = "uart_logs/"+file_name
    imp = await check_default_key.main()
    imp_output = "\n".join(imp)
    # output=""
    # with open("uart_logs/"+file_name, "r") as f:
    #     for i in f:
    #         output+=i
    return {"data":imp_output}

@app.get("/capture_boot_logs/{sampling_rate}/{power_cycle}/{baud_rate}")
async def cap_boot(sampling_rate,power_cycle,baud_rate):
    print(sampling_rate,power_cycle,baud_rate)
    output=""
    capture_uart_boot.main(baud_rate, sampling_rate, power_cycle, power_thread)
    with open(capture_uart_boot.output_file, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/show_raw_boot_logs/{log_name}")
async def cap_boot_show(log_name = None):
    output=""
    if log_name is None:
        log_name = "uart_boot_log"
    with open("uart_logs/"+log_name, "r") as f:
        for i in f:
            output+=i
    print(output)
    return {"data" : output}

@app.get("/detect_baudrate/{sampling_rate}/{power_cycle_delay}")
async def baud_detect(sampling_rate,power_cycle_delay):
    print(sampling_rate, power_cycle_delay, "baud detect")
    detect_baud.main(sampling_rate, power_cycle_delay, power_thread)
    bauds = ""
    
    with open(detect_baud.output_file, "r") as f:
        for i in f:
            bauds+=i
    print("_______________________________________")
    print(bauds)
    return {"dtt": bauds}

@app.post("/cv_scan/")
async def cv_scan(boot_log : BootLog):
    output = find_cve(boot_log.boot_log)
    print(boot_log.boot_log)
    print('output : ',output)
    if output == '':
        output = 'Analysis Done'
    return {'data' : output}


@app.get("/list_devices/{speed}")
async def list_devices(speed:str = '4096'):
    list_output = await helper.list_device_call(speed)
    return {"data": list_output}


@app.get("/download_firm/{filename}")
def down_firm(filename: str = "test"):
    fname = filename
    print("downloading "+fname)
    return FileResponse(FIRM_DIR+"/"+fname+".bin")



@app.get("/dump_firm/{filename}")
def dump_firm(filename:str = 'test'):
    firm_name = filename
    return {"data":helper.dump_firm_call("8000", firm_name+".bin", FIRM_DIR)}




@app.get("/get_strings/{file_name}")
def analyse_firm(file_name):
    filename = file_name
    return {"data" :{"invoked_data":"none", "data": "\n".join(helper.get_strings(FIRM_DIR+"/"+filename))}}
    
@app.get("/get_binwalk/{file_name}")
def analyse_firm_binwalk(file_name):
    filename = file_name
    output = helper.binwalk_des(FIRM_DIR+"/"+filename)
    print(output)
    return {"data": output}


@app.post("/uploadfile/")
async def upload_file(file: UploadFile, baud_rate):
    # Get the file's contents
    file_contents = await file.read()
    print(file_contents)
    # Process the file content (e.g., save it to a file or perform some operation)
    with open(f"uploads/{file.filename}", "wb") as f:
        f.write(file_contents)

    fail_key = "Invalid Password"
    with open(f"uploads/{file.filename}", "r") as f:
        for cred in f:
            print("checking ", cred)
            if check_login(baud_rate, fail_key, cred):
                print("working ", cred)
                return {"data" : cred}
            else:
                print(cred, "Not working")
    
    return {"data" : "No Credentials match"}
"""
