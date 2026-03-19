import aiohttp

from nexus_core.skills.base import BaseSkill


class HttpClientSkill(BaseSkill):

    name = "http_client"

    async def execute(self, url):

        async with aiohttp.ClientSession() as session:

            async with session.get(url) as response:

                data = await response.text()

        return {
            "url": url,
            "response": data[:500]
        }
