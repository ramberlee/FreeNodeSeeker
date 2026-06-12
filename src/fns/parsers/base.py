from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from fns.models import ProxyNode


@dataclass
class ParseResult:
    nodes: list[ProxyNode] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    format_detected: str = "unknown"


class BaseParser(ABC):
    @staticmethod
    def can_parse(text: str) -> bool:
        return False

    @abstractmethod
    def parse(self, text: str, source: str = "") -> ParseResult:
        ...
