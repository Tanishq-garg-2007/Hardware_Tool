from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from ollama import chat

docs = TextLoader("Resume Final.txt").load()

splitter = RecursiveCharacterTextSplitter(chunk_size=500,chunk_overlap=150)
chunks = splitter.split_documents(docs)


embeddings = OllamaEmbeddings(model="qwen2.5-coder:0.5b")
vectorstore = Chroma.from_documents(chunks,embeddings,persist_directory="chroma_db")

def retrieve(query:str) -> str:
    results = vectorstore.similarity_search(query,k=3)
    return "\n\n".join([doc.page_content for doc in results])

def generate_answer(query:str)->str:
    response = chat(
        model = "qwen3.5:0.8b",
        messages=[
            {"role":"user","content":f"Answer the question based on context provider.\n\n {retrieve(query)}"},
            {"role":"user","content":query}
        ]
    )

    return response["message"]["content"]

