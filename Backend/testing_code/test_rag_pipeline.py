import os
import sys
import time

# Ensure Backend directory is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, backend_dir)

from collect_files import collect_all_files
from ChatBot import reindex_database, retrieve, generate_answer

SAMPLE_DIR = os.path.join(backend_dir, "../data/uploads")
MERGED_OUTPUT = os.path.join(backend_dir, "combined_files_output.txt")
SAMPLE_FILE = os.path.join(SAMPLE_DIR, "sample_iot_bootlog.txt")

SAMPLE_LOG_CONTENT = """
U-Boot 2022.04-arm (May 14 2023 - 10:24:15 +0000) IoT-Board-v2
CPU: ARM Cortex-A7 @ 1.2GHz
DRAM: 512 MiB
Flash: 32 MiB SPI NOR Flash (Winbond W25Q256JV)
In:    serial
Out:   serial
Err:   serial
Net:   eth0: ethernet@10000000
Hit any key to stop autoboot:  0 
Security Warning: Insecure JTAG debug mode is enabled on SoC pins 12, 14!
Booting Linux image from 0x80000000 ...

[    0.000000] Booting Linux on physical CPU 0x0
[    0.000000] Linux version 5.10.120-armv7l (gcc version 10.2.1) #42 PREEMPT Wed Jul 12 18:22:10 UTC 2023
[    0.000000] Kernel command line: console=ttyS0,115200 root=/dev/mtdblock2 rw init=/sbin/init
[    1.240012] VFS: Mounted root (squashfs filesystem) readonly on device 31:2.
[    2.110542] Starting /etc/init.d/rcS ...
[    2.310120] Network: eth0 link up, 100Mbps, full duplex
[    2.420890] Starting telnetd daemon on port 23 ...
[    2.510340] Starting dropbear SSH daemon on port 22 ...
[    2.620110] Starting lighttpd web server on port 80 ...
[    2.730450] Starting mosquitto MQTT broker on port 1883 ...
[    2.990110] Security Audit Alert: Hardcoded fallback credentials found in /etc/shadow: root:$1$xyz$password123
[    3.100200] System ready. Welcome to SmartGate IoT Gateway v3.4.1!
"""

def run_test():
    print("=" * 60)
    print("STEP 1: Creating sample IoT log file...")
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    with open(SAMPLE_FILE, "w", encoding="utf-8") as f:
        f.write(SAMPLE_LOG_CONTENT.strip())
    print(f"Sample log created at: {SAMPLE_FILE}")

    print("\n" + "=" * 60)
    print("STEP 2: Merging files via collect_all_files...")
    collect_all_files(SAMPLE_DIR, MERGED_OUTPUT)
    with open(MERGED_OUTPUT, "r", encoding="utf-8") as f:
        merged_preview = f.read()[:300]
    print(f"Merged output generated ({len(merged_preview)} preview chars).")

    print("\n" + "=" * 60)
    print("STEP 3: Indexing database with nomic-embed-text into ChromaDB...")
    start_t = time.time()
    reindex_database()
    index_time = time.time() - start_t
    print(f"Indexing completed in {index_time:.2f} seconds.")

    print("\n" + "=" * 60)
    print("STEP 4: Testing vector similarity search...")
    query = "What open ports and network services are started?"
    context = retrieve(query, k=3)
    print(f"Query: '{query}'")
    print(f"Retrieved Context Snippet:\n{context[:350]}...\n")
    assert len(context) > 50, "Context retrieval failed or empty!"

    print("\n" + "=" * 60)
    print("STEP 5: Testing LLM Answer Generation (RAG pipeline)...")
    test_queries = [
        "What open ports and daemons are started in the boot log?",
        "Are there any hardcoded credentials or security warnings in the log?"
    ]

    for q in test_queries:
        print(f"\n[QUERY]: {q}")
        t0 = time.time()
        answer = generate_answer(q)
        duration = time.time() - t0
        print(f"[TIME]: {duration:.2f}s")
        print(f"[ANSWER]:\n{answer}")
        print("-" * 60)
        assert len(answer) > 20, "Answer generated was empty!"

    print("\n>>> ALL TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    run_test()
