# assistant_rag / ask_assistant() / get_embeddings()

> 14 nodes · cohesion 0.20

## Key Concepts

- **assistant_rag.py** (7 connections) — `Backend/assistant_rag.py`
- **ask_assistant()** (6 connections) — `Backend/assistant_rag.py`
- **index_guide()** (6 connections) — `Backend/assistant_rag.py`
- **get_vectorstore()** (5 connections) — `Backend/assistant_rag.py`
- **retrieve_context()** (4 connections) — `Backend/assistant_rag.py`
- **assistant_chat_endpoint()** (4 connections) — `Backend/main.py`
- **get_embeddings()** (3 connections) — `Backend/assistant_rag.py`
- **assistant_reindex_endpoint()** (3 connections) — `Backend/main.py`
- **AssistantChatRequest** (3 connections) — `Backend/main.py`
- **Any** (1 connections)
- **Retrieves the most relevant context chunks for a given query. Falls back to raw…** (1 connections) — `Backend/assistant_rag.py`
- **Performs RAG query against the IoT Hardware Auditing Guide. Includes fast-path…** (1 connections) — `Backend/assistant_rag.py`
- **Chunks and indexes the IoT Security Hardware Auditing Guide into ChromaDB.** (1 connections) — `Backend/assistant_rag.py`
- **Loads or initializes the Chroma vector store.** (1 connections) — `Backend/assistant_rag.py`

## Relationships

- [main / AnalysisRequest / baud_detect()](main_-_AnalysisRequest_-_baud_detect.md) (7 shared connections)
- [analysis() / brute_force() / cves_endpoint()](analysis_-_brute_force_-_cves_endpoint.md) (2 shared connections)
- [CVEMatch / _load_cve_database() / Loads relevant firmware/bootloader/kernel CVEs directly from the local NVD…](CVEMatch_-__load_cve_database_-_Loads_relevant_firmware-bootloader-kernel_CVEs_directly_from_the_local_NVD….md) (1 shared connections)

## Source Files

- `Backend/assistant_rag.py`
- `Backend/main.py`

## Audit Trail

- EXTRACTED: 28 (100%)
- INFERRED: 0 (0%)
- AMBIGUOUS: 0 (0%)

---

*Part of the graphify knowledge wiki. See [index](index.md) to navigate.*