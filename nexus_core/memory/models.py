from dataclasses import dataclass
from datetime import datetime


@dataclass
class MemoryRecord:

    key: str
    value: dict
    timestamp: datetime
