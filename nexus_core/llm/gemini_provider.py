import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()  # carga el archivo .env

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


class GeminiProvider:
    def __init__(self, api_key):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-pro")

    async def generate_code(self, prompt):
        response = self.model.generate_content(prompt)
        return response.text

