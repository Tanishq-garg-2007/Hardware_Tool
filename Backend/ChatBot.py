import os
import re
import shutil
from dotenv import load_dotenv
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

load_dotenv()

from hardware_config import (
    SLM_NUM_THREADS,
    SLM_CONTEXT_SIZE,
    SLM_TEMPERATURE,
    SLM_TIMEOUT,
    SLM_NUM_PREDICT,
    SLM_MODEL,
    EMBEDDING_MODEL
)

UPLOAD_DIR = os.getenv("UPLOADS_DIR", "../data/uploads")
MERGED_FILE = "combined_files_output.txt"
DB_DIR = os.getenv("CHROMA_DB_DIR", "../data/chroma_db")
COLLECTION_NAME = "file_analysis_rag"

vectorstore = None
embeddings = OllamaEmbeddings(model=EMBEDDING_MODEL)

GREETING_PATTERNS = re.compile(
    r'^\s*(hi+|hello+|hey+|good\s+(morning|afternoon|evening)|howdy|greetings|who\s+are\s+you|help)\b',
    re.IGNORECASE
)
THANKS_PATTERNS = re.compile(
    r'^\s*(thanks?|thank\s+you|thx|cool|ok|okay|great|awesome)\b',
    re.IGNORECASE
)


def clean_log_text(raw_text: str) -> str:
    """
    Compresses consecutive identical lines (e.g. spammy UART polling / retry lines)
    while strictly preserving document structure, headers, and distinct file sections.
    """
    cleaned_lines = []
    last_line = None
    repeat_count = 0

    for line in raw_text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            # Prevent excessive consecutive empty lines
            if last_line != "":
                cleaned_lines.append("")
                last_line = ""
            continue

        if trimmed == last_line:
            repeat_count += 1
            # Keep up to 2 identical consecutive repetitions for context
            if repeat_count < 2:
                cleaned_lines.append(trimmed)
        else:
            repeat_count = 0
            last_line = trimmed
            cleaned_lines.append(trimmed)

    return "\n".join(cleaned_lines)


import hashlib
import json
import datetime
import subprocess
import stat

RETENTION_DAYS = int(os.getenv("RAG_RETENTION_DAYS", "30"))
METADATA_FILE = os.path.join(os.path.dirname(DB_DIR), "rag_index_metadata.json")


def safe_delete_path(path: str) -> bool:
    """
    Safely deletes a file or directory.
    If PermissionError occurs (e.g. root/sudo ownership on Linux/Raspberry Pi 5,
    or read-only locks on Windows), attempts elevated sudo removal or permission fixes.
    """
    if not os.path.exists(path):
        return True

    # Attempt 1: Standard Python deletion
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return True
    except PermissionError as pe:
        print(f"[Notice] PermissionError removing {path}: {pe}. Attempting privileged/sudo fallback...")
    except Exception as e:
        print(f"[Warning] Standard deletion failed on {path}: {e}")

    # Attempt 2: If running on Linux / Raspberry Pi 5, try sudo rm -rf
    if os.name != "nt":
        try:
            # -n flag ensures non-interactive sudo (fails quickly if password is required without hanging)
            cmd = ["sudo", "-n", "rm", "-rf", path]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                print(f"[Success] Successfully removed {path} using sudo.")
                return True
            # Fallback to standard sudo rm -rf
            cmd_std = ["sudo", "rm", "-rf", path]
            res_std = subprocess.run(cmd_std, capture_output=True, text=True, timeout=10)
            if res_std.returncode == 0:
                print(f"[Success] Successfully removed {path} with sudo rm -rf.")
                return True
            else:
                print(f"[Warning] Sudo deletion returned {res_std.returncode}: {res_std.stderr.strip()}")
        except Exception as se:
            print(f"[Warning] Invoking sudo rm failed: {se}")
    else:
        # Windows: attempt to strip read-only attributes and retry
        try:
            for root, dirs, files in os.walk(path):
                for fname in files:
                    full_f = os.path.join(root, fname)
                    try:
                        os.chmod(full_f, stat.S_IWRITE)
                    except Exception:
                        pass
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.exists(path):
                return True
        except Exception:
            pass

    # Attempt 3: If ChromaDB directory, clear all collections via API so vectors are wiped
    try:
        import chromadb
        client = chromadb.PersistentClient(path=path)
        for col in client.list_collections():
            client.delete_collection(col.name)
        print(f"[Fallback] Reset all collections inside ChromaDB at {path}.")
        return True
    except Exception as ce:
        print(f"[Warning] Collection reset fallback also failed: {ce}")

    return not os.path.exists(path)


def compute_file_hash(filepath: str) -> str:
    """Computes SHA-256 hash of a file for content-based cache invalidation."""
    if not os.path.exists(filepath):
        return ""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_index_metadata() -> dict:
    """Reads index metadata containing timestamps, expiration, and content hash."""
    if os.path.exists(METADATA_FILE):
        try:
            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading index metadata: {e}")
    return {}


def save_index_metadata(meta: dict):
    """Saves index metadata with UTC timestamps."""
    try:
        os.makedirs(os.path.dirname(METADATA_FILE), exist_ok=True)
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        print(f"Error saving index metadata: {e}")


def check_and_purge_expired_index() -> bool:
    """
    Checks if the indexed files have exceeded the 30-day retention window.
    If expired, safely deletes ChromaDB and metadata with sudo error handling.
    """
    global vectorstore
    meta = get_index_metadata()
    if not meta or "expires_at" not in meta:
        return False

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = datetime.datetime.fromisoformat(meta["expires_at"])

        if now >= expires_at:
            print(f"[RAG Retention] Index expired on {expires_at.isoformat()}. Auto-purging database...")
            # Release in-memory ChromaDB and SQLite handles before disk deletion
            vectorstore = None
            import gc
            gc.collect()

            safe_delete_path(DB_DIR)
            safe_delete_path(METADATA_FILE)
            print("[RAG Retention] Expired database purged successfully.")
            return True
    except Exception as e:
        print(f"Error evaluating index expiration: {e}")

    return False


def reindex_database(force: bool = False) -> dict:
    """
    Manages vector index lifecycle:
    1. Checks if existing index is within 30 days and file contents match.
    2. If matching, avoids re-indexing, updates last_updated_at, and restarts the 30-day timer.
    3. If new or expired, purges safely and creates fresh ChromaDB index.
    """
    global vectorstore

    # 1. Clean up any expired index first
    check_and_purge_expired_index()

    if not os.path.exists(MERGED_FILE):
        raise FileNotFoundError(f"Merged file '{MERGED_FILE}' not found. Please upload files first.")

    current_hash = compute_file_hash(MERGED_FILE)
    now = datetime.datetime.now(datetime.timezone.utc)
    meta = get_index_metadata()

    # 2. Check for existing valid index match (avoid re-indexing)
    if not force and meta and os.path.exists(DB_DIR) and os.listdir(DB_DIR):
        meta_hash = meta.get("content_hash")
        expires_str = meta.get("expires_at")
        if meta_hash == current_hash and expires_str:
            try:
                expires_at = datetime.datetime.fromisoformat(expires_str)
                if now < expires_at:
                    # RE-START 30-DAY RETENTION TIMER FROM CURRENT MOMENT
                    new_expiry = now + datetime.timedelta(days=RETENTION_DAYS)
                    meta["last_updated_at"] = now.isoformat()
                    meta["expires_at"] = new_expiry.isoformat()
                    meta["retention_days"] = RETENTION_DAYS
                    save_index_metadata(meta)

                    print(f"[RAG Cache] File matches existing index. Re-indexing skipped; 30-day timer renewed until {new_expiry.strftime('%b %d, %Y')}.")
                    return {
                        "status": "cached",
                        "is_cached": True,
                        "message": f"File content matched existing index. Re-indexing skipped; 30-day timer renewed (valid until {new_expiry.strftime('%b %d, %Y')}).",
                        "expires_at": new_expiry.isoformat(),
                        "chunk_count": meta.get("chunk_count", 0)
                    }
            except Exception as e:
                print(f"Notice on cache verification: {e}")

    # 3. New file or force re-index required: safely reset database
    print(f"[RAG Ingestion] Indexing new file content (Hash: {current_hash[:10]}...).")
    if os.path.exists(DB_DIR):
        safe_delete_path(DB_DIR)

    with open(MERGED_FILE, "r", encoding="utf-8", errors="replace") as f:
        raw_text = f.read()

    cleaned_content = clean_log_text(raw_text)

    sections = re.split(r"file start\s*\n", cleaned_content)
    documents = []

    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        lines = sec.splitlines()
        file_source = lines[0].strip() if lines else "Unknown"
        body = "\n".join(lines[1:])
        body = re.sub(r"\nfile end\s*$", "", body).strip()
        if body:
            documents.append(Document(page_content=body, metadata={"source": os.path.basename(file_source)}))

    if not documents:
        documents = [Document(page_content=cleaned_content or "Empty log file.", metadata={"source": "combined"})]

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1200,
        chunk_overlap=150,
        separators=["\n\n", "\n", " ", ""]
    )
    chunks = splitter.split_documents(documents)

    if not chunks:
        chunks = [Document(page_content="No text content extracted.", metadata={"source": "empty"})]

    print(f"File Analysis RAG: Indexing {len(chunks)} chunks into ChromaDB at '{DB_DIR}'...")

    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        collection_name=COLLECTION_NAME,
        persist_directory=DB_DIR
    )

    # 4. Save metadata with 30-day expiration
    new_expiry = now + datetime.timedelta(days=RETENTION_DAYS)
    metadata_payload = {
        "content_hash": current_hash,
        "created_at": now.isoformat(),
        "last_updated_at": now.isoformat(),
        "expires_at": new_expiry.isoformat(),
        "retention_days": RETENTION_DAYS,
        "chunk_count": len(chunks)
    }
    save_index_metadata(metadata_payload)

    print(f"New database indexed successfully. Active for 30 days (until {new_expiry.strftime('%b %d, %Y')}).")
    return {
        "status": "indexed",
        "is_cached": False,
        "message": f"Successfully indexed {len(chunks)} chunks into vector database. Valid for 30 days (until {new_expiry.strftime('%b %d, %Y')}).",
        "expires_at": new_expiry.isoformat(),
        "chunk_count": len(chunks)
    }


def get_vectorstore():
    global vectorstore
    if vectorstore is not None:
        return vectorstore
    if os.path.exists(DB_DIR):
        try:
            vectorstore = Chroma(
                collection_name=COLLECTION_NAME,
                persist_directory=DB_DIR,
                embedding_function=embeddings
            )
        except Exception as e:
            print(f"Chroma DB reload notice: {e}")
    return vectorstore


def retrieve(query: str, k: int = 4) -> str:
    """Retrieves top-k relevant excerpts with source metadata."""
    if check_and_purge_expired_index():
        print("[RAG Retrieval] Notice: Index was expired and purged.")
        return ""
    vs = get_vectorstore()
    if vs is None:
        return ""
    try:
        results = vs.similarity_search(query, k=k)
        formatted_chunks = []
        for doc in results:
            content = doc.page_content.strip()
            if not content:
                continue
            src = doc.metadata.get("source", "")
            prefix = f"[Source: {src}]\n" if src else ""
            formatted_chunks.append(f"{prefix}{content}")
        return "\n\n---\n\n".join(formatted_chunks)
    except Exception as e:
        print(f"Retrieval warning: {e}")
        return ""


def generate_answer(query: str, model: str = None) -> str:
    clean_query = query.strip()
    if not clean_query:
        return "Please provide a question or query regarding your indexed log files."

    # Fast-Path 1: Instant greeting response (<1ms)
    if GREETING_PATTERNS.match(clean_query):
        return (
            "Hello! I am your AI Log & Firmware Assistant. Your files are indexed and active in local memory.\n\n"
            "Ask me any technical question about your boot sequence, errors, open ports, authentication attempts, or hardware configuration!"
        )

    # Fast-Path 2: Instant acknowledgment response (<1ms)
    if THANKS_PATTERNS.match(clean_query):
        return "You're welcome! Feel free to ask any other questions about your indexed log files or security findings."

    # Standard RAG Path: Retrieve relevant context
    active_model = model or SLM_MODEL
    context = retrieve(clean_query, k=4)

    if context:
        context_prompt = f"LOG CONTEXT FROM INDEXED FILES:\n{context[:6000]}"
    else:
        context_prompt = "No direct log excerpt found for this query in the indexed files."

    prompt = (
        f"{context_prompt}\n\n"
        f"USER QUESTION: {clean_query}\n\n"
        "INSTRUCTION: Answer the question directly, concisely, and factually using the log context above. "
        "Highlight any security issues, error codes, passwords, ports, or anomalies found."
    )

    system_instruction = (
        "You are an expert embedded firmware and system log security assistant. "
        "Analyze the provided log context and answer the user's technical questions accurately, "
        "factually, and directly. Do not include lengthy meta-commentary or disclaimers."
    )

    try:
        import ollama
        client = ollama.Client(timeout=SLM_TIMEOUT)

        chat_kwargs = {
            "model": active_model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            "options": {
                "num_thread": SLM_NUM_THREADS,
                "num_ctx": SLM_CONTEXT_SIZE,
                "temperature": SLM_TEMPERATURE,
                "num_predict": SLM_NUM_PREDICT,
            },
            "keep_alive": "15m"
        }

        # Attempt with think=False to disable redundant reasoning loops on thinking models
        try:
            response = client.chat(**chat_kwargs, think=False)
        except (TypeError, Exception):
            # Older ollama client or models that do not accept think kwarg
            response = client.chat(**chat_kwargs)

        # 1. Extract content
        content = response.get("message", {}).get("content", "") or ""
        # Strip any <think>...</think> tags if present in content
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        # 2. Fallback if content was empty but thinking buffer has reasoning
        if not content:
            thinking_txt = response.get("message", {}).get("thinking", "")
            if thinking_txt:
                lines = [
                    l.strip() for l in thinking_txt.splitlines()
                    if l.strip() and not l.strip().lower().startswith(("thinking", "draft", "step", "let me"))
                ]
                if lines:
                    content = "\n".join(lines[-10:])

        if content:
            return content

        if context:
            return f"Here is the relevant excerpt found in your indexed files:\n\n{context[:1200]}"

        return "No specific details could be extracted for this query from the provided log files."

    except Exception as e:
        print(f"Ollama generation warning: {e}")
        if context:
            return f"AI generation encountered an issue ({str(e)}), but here is the matching excerpt from your indexed files:\n\n{context[:1200]}"
        return f"AI generation encountered an error: {str(e)}"

