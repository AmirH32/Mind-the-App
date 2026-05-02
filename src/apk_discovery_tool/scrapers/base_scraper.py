# Mind the App: Detecting Dual-Use Applications
# Copyright (C) 2026 Amir Hassanali
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Base classes and interfaces for APK scrapers.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict


@dataclass
class APKResult:
    """Represents a single APK search result."""

    title: str
    url: str
    source: str  # e.g., "apkmirror", "apkpure", "google"
    description: Optional[str] = None
    version: Optional[str] = None
    developer: Optional[str] = None
    direct_download_url: Optional[str] = None
    fallback_download_url: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialisation to store in JSON."""
        return {
            "title": self.title,
            "url": self.url,
            "source": self.source,
            "description": self.description,
            "version": self.version,
            "developer": self.developer,
            "direct_download_url": self.direct_download_url,
        }


class BaseAPKScraper(ABC):
    """Abstract base class for APK scrapers.
    Provides a consistent interface for scraping APKs from different sources, including search functionality, download link retrieval, rate limiting, and session management.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_results: int = 10,
        rate_limit_delay: float = 7.0,
    ):
        self.timeout = timeout
        self.max_results = max_results
        self.rate_limit_delay = rate_limit_delay

        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.headers = {"User-Agent": self.user_agent}

        self.session = None

    @abstractmethod
    def search(self, query: str) -> Optional[APKResult]:
        """Search for APKs matching a query."""
        raise NotImplementedError

    @abstractmethod
    def get_download_link(self, result: APKResult) -> Optional[str]:
        """Retrieve a direct download link from a search result."""
        raise NotImplementedError

    @abstractmethod
    def search_and_download(
        self, query: str, captured_results: dict
    ) -> tuple[Optional[APKResult], dict]:
        """Search for APKs and retrieve their download links."""
        raise NotImplementedError

    def _rate_limit(self):
        """Pause execution for `rate_limit_delay` seconds to prevent server blocking."""
        import time

        time.sleep(self.rate_limit_delay)

    def __exit__(self):
        """Close the HTTP session if it exists."""
        if self.session:
            self.session.close()
