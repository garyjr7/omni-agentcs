import os
from dotenv import load_dotenv
from google import genai

load_dotenv()  # carga el archivo .env

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


class GeminiProvider:
    def __init__(self, api_key):
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-2.5-pro"

    async def generate_code(self, prompt):
        response = await self.client.aio.models.generate_content(
            model=self.model, contents=prompt
        )
        return response.text
