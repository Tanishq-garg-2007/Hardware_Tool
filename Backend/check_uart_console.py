try:
    import serial
    import serial.serialutil
except ImportError:
    serial = None

import time
import os

OUTPUT_FILE = "uart_logs/uart_console_log.txt"

CONSOLE_TRIGGERS = [
    "login:",
    "username:",
    "password:",
    "root@",
    "busybox",
    "sh-",
    "bash-",
    "=>",
    "# ",
    "$ ",
    "shell",
    "press enter",
    "u-boot",
    "/bin/sh",
]

def check_text_for_console(content: str) -> bool:
    """
    Checks if genuine console prompts or shell indicators are present.
    Explicitly ignores error messages and generic noise.
    """
    if not content:
        return False

    lowered = content.lower()
    
    # Must not be an error string
    if "[error]" in lowered or "[warn]" in lowered and len(content.strip().splitlines()) <= 2:
        return False

    for trigger in CONSOLE_TRIGGERS:
        if trigger in lowered:
            return True

    # Check for shell prompt endings like root@...# or user@...$
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    for line in lines[-5:]: # check recent lines
        if line.endswith("#") or line.endswith("$") or line.endswith("=>"):
            return True

    return False


def check_console(baud_rate: int, power_thread, power_delay: int = 2, listen_time: int = 5):
    """
    Powers cycles the target, opens the UART port, sends CRLF to prompt for shell,
    and returns (success, output, error_message).
    """
    if serial is None:
        return False, "", "pyserial library is not installed or unavailable on this system."

    # ---------------- POWER OFF ---------------- #
    if hasattr(power_thread, "set_state"):
        power_thread.set_state(0)
    time.sleep(power_delay)

    # ---------------- OPEN SERIAL BEFORE POWER ON ---------------- #
    from hardware_config import get_uart_port
    active_port = get_uart_port()
    ser = None
    try:
        ser = serial.Serial(
            port=active_port,
            baudrate=baud_rate,
            timeout=1,
            write_timeout=1,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE
        )
    except Exception as e:
        return False, "", f"Unable to open serial port {active_port}: {str(e)}"

    print(f"[*] Listening on {active_port} at {baud_rate} baud...")

    # ---------------- POWER ON ---------------- #
    if hasattr(power_thread, "set_state"):
        power_thread.set_state(1)

    output = ""

    try:
        start = time.time()
        while time.time() - start < listen_time:
            waiting = ser.in_waiting
            if waiting:
                data = ser.read(waiting)
                decoded = data.decode("utf-8", errors="ignore")
                print(decoded, end="")
                output += decoded
            time.sleep(0.05)

        # Wake the console by sending Carriage Return / Line Feed
        ser.write(b"\r\n")
        ser.flush()

        start = time.time()
        while time.time() - start < 3:
            waiting = ser.in_waiting
            if waiting:
                data = ser.read(waiting)
                decoded = data.decode("utf-8", errors="ignore")
                print(decoded, end="")
                output += decoded
            time.sleep(0.05)

        # If login prompt appears, try standard IoT credentials
        if "login" in output.lower() or "username" in output.lower():
            ser.write(b"admin\r\n")
            ser.flush()
            start = time.time()
            while time.time() - start < 2:
                waiting = ser.in_waiting
                if waiting:
                    data = ser.read(waiting)
                    decoded = data.decode("utf-8", errors="ignore")
                    print(decoded, end="")
                    output += decoded
                time.sleep(0.05)

        return True, output, None

    except Exception as e:
        return False, output, f"Error communicating during console check: {str(e)}"

    finally:
        if ser:
            try:
                ser.close()
            except Exception:
                pass


def main(baud_rate: int, power_thread) -> dict:
    os.makedirs("uart_logs", exist_ok=True)

    if os.path.exists(OUTPUT_FILE):
        try:
            os.remove(OUTPUT_FILE)
        except Exception:
            pass

    success, output, error_msg = check_console(int(baud_rate), power_thread)

    # Save log to file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        if success:
            f.write(output or "[No serial traffic received]")
        else:
            f.write(f"[Hardware Error]: {error_msg}\n{output}")

    if not success:
        return {
            "success": False,
            "is_available": False,
            "status": "error",
            "message": error_msg,
            "data": f"Error: {error_msg}",
            "log": error_msg
        }

    is_avail = check_text_for_console(output)

    if is_avail:
        return {
            "success": True,
            "is_available": True,
            "status": "console is available",
            "data": "console is available",
            "message": "Interactive UART Console Prompt Detected",
            "log": output
        }
    else:
        return {
            "success": True,
            "is_available": False,
            "status": "console is not available",
            "data": "console is not available",
            "message": "No interactive console prompt detected at this baudrate",
            "log": output or "No response from device"
        }
