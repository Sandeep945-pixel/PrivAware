import os
import faiss
import pickle
import re
from sentence_transformers import SentenceTransformer
from typing import List

embedder = SentenceTransformer('all-MiniLM-L6-v2')

def load_markdown_chunks(file_path: str) -> List[str]:
    """
    Load and clean markdown file. Split into role-based chunks using '## Role:' header.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    # Normalize line endings and remove any strange characters
    text = text.replace("\r\n", "\n").replace("\x0c", "").strip()

    # Split by role
    chunks = re.split(r"---+", text)  # separator between roles
    cleaned_chunks = [chunk.strip() for chunk in chunks if "Role:" in chunk]

    return cleaned_chunks

def store_faiss_index(chunks: List[str], index_path="rules_index.faiss", mapping_path="rules_chunks.pkl"):
    """
    Encode chunks using sentence-transformers and store FAISS index and chunk map.
    """
    embeddings = embedder.encode(chunks)
    dim = embeddings.shape[1]

    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)

    faiss.write_index(index, index_path)
    with open(mapping_path, "wb") as f:
        pickle.dump(chunks, f)

    print(f"✅ Indexed {len(chunks)} rule chunks into FAISS.")

if __name__ == "__main__":
    file_path = "access_control_rules.md"  # ensure this is cleaned markdown
    chunks = load_markdown_chunks(file_path)
    store_faiss_index(chunks)
