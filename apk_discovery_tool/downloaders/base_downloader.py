from abc import ABC, abstractmethod
import os
from typing import Optional


class BaseDownloader(ABC):
    """Abstract base class for all downloaders."""

    def __init__(self, download_dir: str):
        self.download_dir = os.path.abspath(download_dir)
        os.makedirs(self.download_dir, exist_ok=True)

    @abstractmethod
    def download_file(self, url: str) -> Optional[str]:
        """Download a file from the given URL and return the local file path."""
        pass

    def close(self):
        """Cleanup method for downloaders that need to close sessions/browsers."""
        pass
