from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RawContent:
    text: str
    source_url: str
    collector_name: str
    format_hint: str | None = None  # "base64", "yaml", "uri", or None for auto-detect


class BaseCollector(ABC):
    def __init__(self, name: str = ""):
        self.name = name or self.__class__.__name__

    @abstractmethod
    async def collect(self) -> list[RawContent]:
        ...
