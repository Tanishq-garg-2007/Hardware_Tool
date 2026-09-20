import os
import sys
import shutil
import argparse
from typing import List, Dict, Any
import re
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
import ollama

GUIDE_FILE_PATH = os.path.join(os.path.dirname(__file__), "docs", "iot_security_guide.txt")
from dotenv import load_dotenv
load_dotenv()
ASSISTANT_DB_DIR = os.getenv("CHROMA_ASSISTANT_DB_DIR", os.path.join(os.path.dirname(__file__), "../data/chroma_assistant_db"))
EMBEDDING_MODEL = "nomic-embed-text"
DEFAULT_CHAT_MODEL = "qwen3.5:0.8b"

SYSTEM_PROMPT = """You are the specialized AI Assistant for the IoT Security Research Lab at IIIT Allahabad.
Your goal is to guide users through the Hardware Auditing Tool and explain its features, step-by-step auditing workflows, hardware modes, and security analysis capabilities.

Instructions:
1. Answer the user's questions clearly, concisely, and accurately based on the provided IoT Security Guide context.
2. Keep responses brief (under 120 words) and directly actionable with clear bullet points.
3. If asked about the recommended order of steps, list the workflow clearly (e.g., Pin setup -> Detect Baud -> Capture Bootlog -> Analyze Bootlog -> Console Check/Glitching -> SPI extraction -> Firmware analysis -> Hardcoded Passwords -> CVE scanning).
4. If asked about Relay vs OCTOCOPLOR, explain the differences clearly.
5. If the question is outside the scope of IoT security / this tool, politely steer the conversation back to the hardware auditing platform.
"""


_vectorstore = None

def get_embeddings():
    return OllamaEmbeddings(model=EMBEDDING_MODEL)

def index_guide(force: bool = False) -> str:
    """
    Chunks and indexes the IoT Security Hardware Auditing Guide into ChromaDB.
    """
    global _vectorstore

    if not os.path.exists(GUIDE_FILE_PATH):
        raise FileNotFoundError(f"Guide file not found at: {GUIDE_FILE_PATH}")

    if force and os.path.exists(ASSISTANT_DB_DIR):
        print(f"Clearing existing assistant vectorstore collections at {ASSISTANT_DB_DIR}...")
        try:
            import chromadb
            client = chromadb.PersistentClient(path=ASSISTANT_DB_DIR)
            for col in client.list_collections():
                client.delete_collection(col.name)
        except Exception as e:
            print(f"Assistant DB collection reset warning: {e}")
            try:
                shutil.rmtree(ASSISTANT_DB_DIR, ignore_errors=True)
            except Exception:
                pass

    print(f"Loading document: {GUIDE_FILE_PATH}...")
    loader = TextLoader(GUIDE_FILE_PATH, encoding="utf-8")
    docs = loader.load()

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=120,
        separators=["\n\n", "\n", " ", ""]
    )
    chunks = splitter.split_documents(docs)
    print(f"Generated {len(chunks)} text chunks from guide.")

    print(f"Generating embeddings with '{EMBEDDING_MODEL}' and saving to '{ASSISTANT_DB_DIR}'...")
    embeddings = get_embeddings()
    _vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=ASSISTANT_DB_DIR
    )
    print("Assistant Knowledge Base indexed successfully!")
    return f"Indexed {len(chunks)} chunks into ChromaDB."

def get_vectorstore():
    """
    Loads or initializes the Chroma vector store.
    """
    global _vectorstore
    if _vectorstore is not None:
        return _vectorstore

    embeddings = get_embeddings()
    if os.path.exists(ASSISTANT_DB_DIR) and os.listdir(ASSISTANT_DB_DIR):
        _vectorstore = Chroma(
            persist_directory=ASSISTANT_DB_DIR,
            embedding_function=embeddings
        )
    else:
        print("Vectorstore not found. Auto-indexing guide now...")
        index_guide(force=True)
    return _vectorstore

GREETING_PATTERNS = re.compile(
    r"^(hi|hello|hey|heya|howdy|greetings|good\s+(morning|afternoon|evening)|who\s+are\s+you|what\s+can\s+you\s+do|help)[\s?!.]*$",
    re.IGNORECASE
)

THANKS_PATTERNS = re.compile(
    r"^(thanks|thank\s+you|thx|great|awesome|ok|okay|got\s+it|nice)[\s?!.]*$",
    re.IGNORECASE
)

def retrieve_context(query: str, k: int = 3) -> str:
    """
    Retrieves the most relevant context chunks for a given query.
    Falls back to raw guide text if vectorstore is unavailable.
    """
    try:
        vs = get_vectorstore()
        results = vs.similarity_search(query, k=k)
        if results:
            return "\n\n---\n\n".join([doc.page_content for doc in results])
    except Exception as e:
        print(f"[Warning] Vector retrieval failed ({e}). Falling back to direct guide reading.")

    if os.path.exists(GUIDE_FILE_PATH):
        with open(GUIDE_FILE_PATH, "r", encoding="utf-8") as f:
            return f.read()[:1500]
    return ""

def ask_assistant(query: str, model: str = DEFAULT_CHAT_MODEL) -> Dict[str, Any]:
    """
    Performs RAG query against the IoT Hardware Auditing Guide.
    Includes fast-path for conversational greetings to achieve zero-latency responses.
    """
    clean_query = query.strip()

    # Fast-Path 1: Instant response for greetings
    if GREETING_PATTERNS.match(clean_query):
        return {
            "query": query,
            "answer": "Hello! I am the IoT Security Research Lab Assistant at IIIT Allahabad. I am here to guide you through hardware auditing, UART serial analysis, boot log capture, voltage glitching, SPI extraction, and firmware security. How can I help you today?",
            "model_used": "fast-path (instant)",
            "context_length": 0
        }

    # Fast-Path 2: Instant response for thanks/acknowledgments
    if THANKS_PATTERNS.match(clean_query):
        return {
            "query": query,
            "answer": "You're very welcome! Feel free to ask whenever you need guidance on hardware connections, glitch timing, or firmware vulnerability assessment.",
            "model_used": "fast-path (instant)",
            "context_length": 0
        }

    # Standard Path: Retrieve top-3 chunks and query local Ollama LLM
    context = retrieve_context(clean_query, k=3)

    prompt = f"""Context from IoT Security Research Lab Auditing Guide:
=====================================================
{context}
=====================================================

User Question: {clean_query}

Please provide a clear, concise, and structured response:"""

    try:
        from hardware_config import SLM_NUM_THREADS, SLM_TEMPERATURE
        options = {
            "num_thread": SLM_NUM_THREADS,
            "num_ctx": 2048,
            "temperature": SLM_TEMPERATURE,
            "num_predict": 350
        }

        target_model = model or DEFAULT_CHAT_MODEL
        try:
            try:
                response = ollama.chat(
                    model=target_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    think=False,
                    options=options
                )
            except TypeError:
                response = ollama.chat(
                    model=target_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    options=options
                )
        except Exception as model_err:
            if target_model != DEFAULT_CHAT_MODEL:
                print(f"[WARN] Assistant model {target_model} failed ({model_err}). Falling back to {DEFAULT_CHAT_MODEL}...")
                target_model = DEFAULT_CHAT_MODEL
                try:
                    response = ollama.chat(
                        model=target_model,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        think=False,
                        options=options
                    )
                except TypeError:
                    response = ollama.chat(
                        model=target_model,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        options=options
                    )
            else:
                raise model_err

        raw_content = response.get("message", {}).get("content", "")
        raw_thinking = response.get("message", {}).get("thinking", "")
        
        # Clean thinking tags and extract the concrete answer
        if "</think>" in raw_content:
            clean_answer = raw_content.split("</think>")[-1].strip()
        elif "<think>" in raw_content:
            # If think tag was unclosed, extract drafted bullet points or answer
            bullets = re.findall(r'(?:[-*•]|\d+\.)\s+[^\n]+', raw_content)
            if bullets:
                clean_answer = "\n".join(bullets)
            else:
                clean_answer = re.sub(r'<think>[\s\S]*', '', raw_content).strip()
        else:
            clean_answer = raw_content.strip()

        # If content was empty, try raw_thinking
        if not clean_answer and raw_thinking:
            if "</think>" in raw_thinking:
                clean_answer = raw_thinking.split("</think>")[-1].strip()
            else:
                bullets = re.findall(r'(?:[-*•]|\d+\.)\s+[^\n]+', raw_thinking)
                clean_answer = "\n".join(bullets) if bullets else raw_thinking.strip()

        answer = clean_answer or "I processed your request, but no response text was generated. Please try rephrasing."
        model = target_model
    except Exception as e:
        answer = f"Error querying local AI model ({model}): {str(e)}. Make sure Ollama is running ('ollama serve') and model is pulled ('ollama pull {model}')."

    return {
        "query": query,
        "answer": answer,
        "model_used": model,
        "context_length": len(context)
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Assistant RAG CLI")
    parser.add_argument("--index", action="store_true", help="Re-index the guide into ChromaDB")
    parser.add_argument("--query", type=str, default="What is the recommended workflow order for auditing a device?", help="Ask a question")
    parser.add_argument("--model", type=str, default=DEFAULT_CHAT_MODEL, help="Ollama model to use")

    args = parser.parse_args()

    if args.index:
        index_guide(force=True)
    else:
        print(f"\n[Query]: {args.query}\n[Model]: {args.model}")
        result = ask_assistant(args.query, model=args.model)
        print("\n[Assistant Response]:\n")
        print(result["answer"])
