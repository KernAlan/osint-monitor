"""Abstract base collector interface."""

from abc import ABC, abstractmethod

from osint_monitor.core.models import RawItemModel


class BaseCollector(ABC):
    """Base class for all source collectors."""

    def __init__(self, name: str, source_type: str, url: str, **kwargs):
        self.name = name
        self.source_type = source_type
        self.url = url
        self.max_items = kwargs.get("max_items", 20)

    @abstractmethod
    def collect(self) -> list[RawItemModel]:
        """Collect items from the source. Returns list of raw items."""
        ...

    def health_check(self) -> bool:
        """Check if the source is reachable."""
        try:
            items = self.collect()
            return len(items) > 0
        except Exception:
            return False

    def __repr__(self):
        return f"<{self.__class__.__name__} name={self.name!r}>"
