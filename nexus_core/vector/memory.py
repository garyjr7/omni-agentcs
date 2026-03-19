from nexus_core.vector.embeddings import EmbeddingClient
from nexus_core.vector.store import VectorStore


class VectorMemory:

    def __init__(self):

        self.embedder = EmbeddingClient()
        self.store = VectorStore()

    def add_memory(self, text, metadata):

        vector = self.embedder.embed(text)

        self.store.add(vector, metadata)

    def search_memory(self, query):

        q_vector = self.embedder.embed(query)

        return self.store.search(q_vector)
