import requests
from pathlib import Path
from tqdm import tqdm

# ── CONFIG ───────────────────────────────────────────────
LOG_PATH    = "bootlog_TpLink_TLWR8445N.txt"
MODEL_ID    = "hf.co/hugging-quants/Llama-3.2-1B-Instruct-Q8_0-GGUF:Q8_0"
CHUNK_CHARS = 1000
OUTPUT_FILE = "Bootlog_output.md"

# ── SYSTEM PROMPT ────────────────────────────────────────
SYSTEM_PROMPT = """You are a Linux boot log analyzer.

INPUT: Raw Linux boot log text.

GOAL: Remove noise and keep only useful problems.

DISCARD:
- Reached target, Started, Mounted, Listening on
- Successful service starts
- INFO-only messages
- Normal kernel init messages

KEEP ONLY:
- ERROR, FAILED, WARN, CRITICAL, PANIC, OOPS
- Service timeouts, retries, dependency failures
- Hardware issues (disk, fs, USB, SPI, I2C, PCI, firmware, memory, CPU)
- Long or delayed startups

PROCESS:
- Merge identical messages
- Count occurrences
- Keep time order

OUTPUT:
- ONLY a Markdown table:
| Severity | Timestamp | Component | Message | Count | Impact |

If no issues:
Boot completed successfully. No critical issues detected.

RULES:
- No raw log lines
- No explanations
- No hallucinations
"""

# ── CHUNKER ──────────────────────────────────────────────
def chunks(text, limit=CHUNK_CHARS):
    buf, size = [], 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit and buf:
            yield "".join(buf)
            buf, size = [], 0
        buf.append(line)
        size += len(line)
    if buf:
        yield "".join(buf)

# ── OLLAMA CALL ──────────────────────────────────────────
def ollama_chat(chunk):
    payload = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": chunk}
        ],
        "stream": False
    }

    r = requests.post(
        "http://localhost:11434/api/chat",
        json=payload,
        timeout=(5, 300)
    )
    r.raise_for_status()
    return r.json()["message"]["content"]

# ── MAIN ─────────────────────────────────────────────────
raw_log = Path(LOG_PATH).read_text(errors="ignore")

with open(OUTPUT_FILE, "a") as out:
    for part in tqdm(list(chunks(raw_log)), desc="Analyzing boot log"):
        try:
            result = ollama_chat(part).strip()
            if result:
                out.write(result + "\n\n")
        except Exception as e:
            print("Error:", e)

print(f"\n✅ Cleaned boot-log analysis saved to {OUTPUT_FILE}")
