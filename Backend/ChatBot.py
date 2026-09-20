import os
import sys
import re
import shutil
import hashlib
import json
import datetime
import subprocess
import stat
import gc
from dotenv import load_dotenv

load_dotenv()

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from hardware_config import (
    SLM_NUM_THREADS,
    SLM_CONTEXT_SIZE,
    SLM_TEMPERATURE,
    SLM_TIMEOUT,
    SLM_NUM_PREDICT,
    SLM_MODEL,
    EMBEDDING_MODEL
)
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document

def _resolve_dir(path_str: str, base: str) -> str:
    if os.path.isabs(path_str):
        return path_str
    return os.path.abspath(os.path.join(base, path_str))

# Canonical Absolute Paths (anchored to Backend directory)
UPLOAD_DIR = _resolve_dir(os.getenv("UPLOADS_DIR", "../data/uploads"), _BASE_DIR)
MERGED_FILE = _resolve_dir(os.getenv("MERGED_FILE", "combined_files_output.txt"), _BASE_DIR)
DB_DIR = _resolve_dir(os.getenv("CHROMA_DB_DIR", "../data/chroma_db"), _BASE_DIR)
COLLECTION_NAME = "file_analysis_rag"
RETENTION_DAYS = int(os.getenv("RAG_RETENTION_DAYS", "30"))
METADATA_FILE = os.path.join(os.path.dirname(DB_DIR), "rag_index_metadata.json")

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

TECHNICAL_TERMS_PATTERN = re.compile(r'\b(0x[0-9a-fA-F]+|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9_.-]{3,})\b')
DOMAIN_SYNONYMS = {
    "mac": ["eth", "mac", "ethernet", "hwaddr", "00:"],
    "ip": ["ipaddr", "inet", "ip", "192.", "10."],
    "network": ["eth0", "r8168", "net", "interface", "link"],
    "boot": ["bootcmd", "bootargs", "bootdelay", "vmlinux", "u-boot", "bootm"],
    "baudrate": ["baudrate", "console", "ttyS"],
    "memory": ["dram", "ddr", "ram", "memory", "mb", "mib"],
    "error": ["panic", "error", "fault", "failed", "segfault", "warn"],
}


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
    3. If new or expired, purges safely and creates fresh ChromaDB index using line-aware chunking.
    """
    global vectorstore

    # 1. Clean up any expired index first
    check_and_purge_expired_index()

    if not os.path.exists(MERGED_FILE):
        raise FileNotFoundError(f"Merged file '{MERGED_FILE}' not found. Please upload files first.")

    current_hash = compute_file_hash(MERGED_FILE)
    now = datetime.datetime.now(datetime.timezone.utc)
    meta = get_index_metadata()

    # 2. Check for existing valid index match (avoid redundant re-indexing)
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

    # 3. New file or force re-index required: cleanly reset the collection via ChromaDB API
    print(f"[RAG Ingestion] Indexing new file content (Hash: {current_hash[:10]}...).")
    vectorstore = None
    gc.collect()

    try:
        import chromadb
        chroma_client = chromadb.PersistentClient(path=DB_DIR)
        try:
            chroma_client.delete_collection(COLLECTION_NAME)
            print(f"[RAG Ingestion] Reset Chroma collection '{COLLECTION_NAME}' via API.")
        except Exception:
            pass
    except Exception as ce:
        print(f"[Notice] Chroma client collection reset note: {ce}")
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
            documents.append(Document(
                page_content=body,
                metadata={
                    "source": os.path.basename(file_source),
                    "full_path": file_source
                }
            ))

    if not documents:
        documents = [Document(page_content=cleaned_content or "Empty log file.", metadata={"source": "combined", "full_path": MERGED_FILE})]

    # Line-aware chunking: preserves complete log lines and error structures
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=100,
        separators=["\n\n", "\n", " "],
        keep_separator=True
    )
    chunks = splitter.split_documents(documents)

    if not chunks:
        chunks = [Document(page_content="No text content extracted.", metadata={"source": "empty", "chunk_index": 0})]
    else:
        for idx, c in enumerate(chunks):
            c.metadata["chunk_index"] = idx

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
    if os.path.exists(DB_DIR) and os.path.isdir(DB_DIR):
        try:
            vectorstore = Chroma(
                collection_name=COLLECTION_NAME,
                persist_directory=DB_DIR,
                embedding_function=embeddings
            )
        except Exception as e:
            print(f"Chroma DB reload notice: {e}")
    return vectorstore


DOMAIN_PATTERNS = {
    "mac": re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b|\b(eth[0-9%]?|ethernet|hwaddr)\b', re.IGNORECASE),
    "ip": re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(ipaddr|netmask|gateway|dns)\b', re.IGNORECASE),
    "baudrate": re.compile(r'\bbaudrate=\d+\b|\bconsole=tty\w+,\d+\b|\b(baudrate|115200|57600|9600)\b', re.IGNORECASE),
    "boot": re.compile(r'\b(bootcmd|bootargs|bootdelay|vmlinux|u-boot|bootm|Starting\s+kernel)\b', re.IGNORECASE),
    "memory": re.compile(r'\b(dram|ddr|ram|memory)\b:\s*\d+|\b\d+\s*(?:MB|MiB|GB|GiB)\b', re.IGNORECASE),
    "error": re.compile(r'\b(panic|segfault|segmentation\s+fault|failed|error|crash|fault)\b', re.IGNORECASE),
}


def extract_search_terms(query: str) -> tuple[list, list]:
    """Extracts technical tokens and matching domain regex patterns from query."""
    primary_terms = []
    secondary_patterns = []
    stopwords = {
        "what", "when", "where", "which", "show", "list", "check", "tell",
        "explain", "does", "have", "with", "from", "into", "that", "this",
        "your", "file", "logs", "log", "the", "and", "for", "are", "address",
        "device", "system"
    }

    # 1. Primary literal tokens from query
    for token in TECHNICAL_TERMS_PATTERN.findall(query):
        t_clean = token.strip()
        if t_clean.lower() not in stopwords:
            primary_terms.append(t_clean)

    # 2. Secondary domain patterns
    query_lower = query.lower()
    for domain_key, pattern in DOMAIN_PATTERNS.items():
        if re.search(rf"\b{domain_key}\b", query_lower):
            secondary_patterns.append(pattern)

    return primary_terms, secondary_patterns


def retrieve_exact_lines(primary_terms: list, secondary_patterns: list = None, max_snippets: int = 3) -> list:
    """Finds matching lines and immediate surrounding context with contiguous block clustering."""
    if not primary_terms and not secondary_patterns:
        return []
    if not os.path.exists(MERGED_FILE):
        return []

    matching_snippets = []
    try:
        with open(MERGED_FILE, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total = len(all_lines)
        matched_indices = []

        # Step 1: Match primary literal terms
        if primary_terms:
            for i, line in enumerate(all_lines):
                trimmed = line.strip()
                if not trimmed or trimmed in ("file start", "file end") or trimmed.startswith("/"):
                    continue
                line_lower = trimmed.lower()
                if any(t.lower() in line_lower for t in primary_terms):
                    matched_indices.append(i)

        # Step 2: If primary matches are few, evaluate secondary domain patterns
        if len(matched_indices) < 2 and secondary_patterns:
            for i, line in enumerate(all_lines):
                trimmed = line.strip()
                if not trimmed or trimmed in ("file start", "file end") or trimmed.startswith("/"):
                    continue
                for pat in secondary_patterns:
                    if pat.search(trimmed) and i not in matched_indices:
                        matched_indices.append(i)
                        break

        if not matched_indices:
            return []

        matched_indices.sort()

        # Step 3: Cluster nearby matched line numbers into contiguous coherent blocks
        clusters = []
        current_cluster = [matched_indices[0]]
        for idx in matched_indices[1:]:
            if idx - current_cluster[-1] <= 3:
                current_cluster.append(idx)
            else:
                clusters.append(current_cluster)
                current_cluster = [idx]
                if len(clusters) >= max_snippets:
                    break
        if current_cluster and len(clusters) < max_snippets:
            clusters.append(current_cluster)

        # Step 4: Format snippets with 1 line of preceding/succeeding context
        for cluster in clusters[:max_snippets]:
            start_line = max(0, cluster[0] - 1)
            end_line = min(total, cluster[-1] + 2)
            snippet = "\n".join(
                all_lines[k].strip() for k in range(start_line, end_line)
                if all_lines[k].strip() not in ("file start", "file end")
            )
            if snippet and snippet not in matching_snippets:
                matching_snippets.append(snippet)

    except Exception as e:
        print(f"Notice on exact line retrieval: {e}")

    return matching_snippets


def retrieve(query: str, k: int = 3) -> str:
    """Retrieves top-k relevant excerpts with source metadata from vector store."""
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


def retrieve_hybrid(query: str, k_vector: int = 3) -> str:
    """
    Hybrid retrieval:
    Combines dense vector similarity search with sparse exact keyword/pattern matching.
    Capped at ~2,200 characters to guarantee fast (<5s) prompt evaluation on Raspberry Pi 5.
    """
    context_sections = []

    # 1. Sparse exact keyword / domain pattern extraction
    primary_terms, secondary_patterns = extract_search_terms(query)
    exact_snippets = retrieve_exact_lines(primary_terms, secondary_patterns, max_snippets=3)
    if exact_snippets:
        context_sections.append("EXACT MATCHING LOG EXCERPTS:\n" + "\n---\n".join(exact_snippets))

    # 2. Dense vector similarity search
    vector_text = retrieve(query, k=k_vector)
    if vector_text:
        context_sections.append("RELEVANT LOG SECTIONS:\n" + vector_text)

    combined = "\n\n".join(context_sections).strip()

    # 3. Budget constraint for Pi 5: max 2,400 chars (~500-600 prompt tokens)
    if len(combined) > 2400:
        combined = combined[:2400]

    return combined


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

    # Hybrid Retrieval (Dense Vector Search + Sparse Token Matching)
    active_model = model or SLM_MODEL
    context = retrieve_hybrid(clean_query, k_vector=3)

    if context:
        context_prompt = f"LOG CONTEXT FROM INDEXED FILES:\n{context}"
    else:
        context_prompt = "No direct log excerpt found for this query in the indexed files."

    prompt = (
        f"{context_prompt}\n\n"
        f"USER QUESTION: {clean_query}\n\n"
        "INSTRUCTIONS:\n"
        "1. Answer the question directly and factually using ONLY the log context provided above.\n"
        "2. State or quote exact variable assignments, version numbers, addresses, or error lines (e.g. 'baudrate=115200') found in the log.\n"
        "3. Keep the response concise, technical, and direct (1-3 sentences)."
    )

    system_instruction = (
        "You are an expert embedded firmware and system log security assistant. "
        "Analyze the provided log context and answer the user's technical questions accurately, "
        "factually, and directly without preamble or meta-commentary."
    )

    # Models to try: primary active_model, with fast fallback to qwen3:0.6b if needed
    models_to_try = [active_model]
    if active_model != "qwen3:0.6b":
        models_to_try.append("qwen3:0.6b")

    try:
        import ollama
        client = ollama.Client(timeout=SLM_TIMEOUT)

        for mdl in models_to_try:
            try:
                chat_kwargs = {
                    "model": mdl,
                    "messages": [
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": prompt}
                    ],
                    "options": {
                        "num_thread": SLM_NUM_THREADS,
                        "num_ctx": 2048,           # Memory and cache optimized for Pi 5
                        "temperature": 0.1,
                        "num_predict": 300,        # Concise technical output (fast 3-10s generation)
                    },
                    "keep_alive": "15m"
                }

                try:
                    response = client.chat(**chat_kwargs, think=False)
                except (TypeError, Exception):
                    response = client.chat(**chat_kwargs)

                # 1. Robust response parsing (handles Pydantic ChatResponse and dict)
                content = ""
                if hasattr(response, "message") and hasattr(response.message, "content"):
                    content = response.message.content or ""
                elif isinstance(response, dict):
                    content = response.get("message", {}).get("content", "") or ""

                # Strip any <think>...</think> tags if present in content
                content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

                # 2. Fallback if content was empty but thinking buffer has reasoning
                if not content:
                    thinking_txt = ""
                    if hasattr(response, "message") and hasattr(response.message, "thinking"):
                        thinking_txt = response.message.thinking or ""
                    elif isinstance(response, dict):
                        thinking_txt = response.get("message", {}).get("thinking", "") or ""

                    if thinking_txt:
                        lines = [
                            l.strip() for l in thinking_txt.splitlines()
                            if l.strip() and not l.strip().lower().startswith(("thinking", "draft", "step", "let me", "1.", "2.", "*"))
                        ]
                        if lines:
                            content = "\n".join(lines[-8:])

                if content:
                    return content

            except Exception as me:
                print(f"Model {mdl} invocation error: {me}")
                continue

        # If LLM attempts return empty or fail, return the exact matching excerpt
        if context:
            return f"Here are the matching excerpts extracted from your indexed files:\n\n{context[:1200]}"

        return "No specific details could be extracted for this query from the provided log files."

    except Exception as e:
        print(f"Ollama generation warning: {e}")
        if context:
            return f"AI generation encountered an issue ({str(e)}), but here is the matching excerpt from your indexed files:\n\n{context[:1200]}"
        return f"AI generation encountered an error: {str(e)}"

