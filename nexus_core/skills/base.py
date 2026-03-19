class BaseSkill:

    name = "base_skill"

    async def execute(self, **kwargs):
        raise NotImplementedError
