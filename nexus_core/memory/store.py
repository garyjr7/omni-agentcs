import chromadb
import json
from datetime import datetime
from pathlib import Path

CHROMA_PATH = str(Path(__file__).parent.parent.parent / "data" / "junior_memory_db")

class MemoryStore:
    """Almacenamiento persistente usando ChromaDB."""

    def __init__(self, collection_name: str):
        self._client = chromadb.PersistentClient(path=CHROMA_PATH)
        self.collection = self._client.get_or_create_collection(name=collection_name)

    def write(self, key: str, value: dict):
        self.collection.upsert(
            ids=[key],
            documents=[json.dumps(value, ensure_ascii=False)],
            metadatas=[{"timestamp": datetime.utcnow().isoformat()}]
        )

    def read(self, key: str):
        result = self.collection.get(ids=[key])
        if result and result["documents"]:
            return json.loads(result["documents"][0])
        return None

    def search(self, query: str, n_results: int = 5) -> list:
        """Búsqueda semántica por similitud."""
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=min(n_results, self.collection.count())
            )
            items = []
            for i, doc in enumerate(results["documents"][0]):
                items.append({
                    "key": results["ids"][0][i],
                    "value": json.loads(doc),
                    "distance": results["distances"][0][i] if results.get("distances") else None,
                })
            return items
        except Exception:
            return []

    def list_keys(self) -> list:
        return self.collection.get()["ids"]

    def count(self) -> int:
        return self.collection.count()
