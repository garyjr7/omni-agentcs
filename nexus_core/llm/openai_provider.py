import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # carga el archivo .env

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

class OpenAIProvider:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)

    async def generate_code(self, prompt):
        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You generate Python AI agents."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
