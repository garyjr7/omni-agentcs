from nexus_core.memory.store import MemoryStore

class MemoryManager:
    """API de alto nivel para los 3 tipos de memoria de agentes."""

    def __init__(self):
        self.short_term  = MemoryStore("nexus_short_term")
        self.task_memory = MemoryStore("nexus_task_memory")
        self.knowledge   = MemoryStore("nexus_knowledge")

    # ── Short-term (memoria de trabajo) ──────────────────────
    def remember_short_term(self, key: str, data: dict):
        self.short_term.write(key, data)

    def recall_short_term(self, key: str):
        return self.short_term.read(key)

    # ── Task memory (memoria episódica) ───────────────────────
    def remember_task(self, task_id: str, data: dict):
        self.task_memory.write(task_id, data)

    def recall_task(self, task_id: str):
        return self.task_memory.read(task_id)

    def search_tasks(self, query: str, n: int = 5) -> list:
        return self.task_memory.search(query, n)

    # ── Knowledge base (memoria semántica) ────────────────────
    def remember_knowledge(self, key: str, data: dict):
        self.knowledge.write(key, data)

    def recall_knowledge(self, key: str):
        return self.knowledge.read(key)

    def search_knowledge(self, query: str, n: int = 5) -> list:
        """Búsqueda semántica — encuentra conocimiento similar a la query."""
        return self.knowledge.search(query, n)

    def stats(self) -> dict:
        return {
            "short_term": self.short_term.count(),
            "task_memory": self.task_memory.count(),
            "knowledge": self.knowledge.count(),
        }
