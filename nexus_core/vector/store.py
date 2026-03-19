import numpy as np

class VectorStore:

    def __init__(self):

        self.vectors = []
        self.metadata = []

    def add(self, vector, meta):

        self.vectors.append(vector)
        self.metadata.append(meta)

    def similarity(self, v1, v2):

        v1 = np.array(v1)
        v2 = np.array(v2)

        return np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))

    def search(self, query_vector, top_k=3):

        scores = []

        for i, vector in enumerate(self.vectors):

            score = self.similarity(query_vector, vector)

            scores.append((score, self.metadata[i]))

        scores.sort(reverse=True, key=lambda x: x[0])

        return scores[:top_k]
