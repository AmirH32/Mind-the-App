"""
Base classes and interfaces for APK scrapers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict


@dataclass
class APKResult:
    """Represents a single APK search result.

    Attributes:
        title (str): Name or title of the APK.
        url (str): URL of the search result page.
        source (str): The source website (e.g., "apkmirror", "apkpure", "google").
        description (Optional[str]): Short description of the APK.
        version (Optional[str]): APK version string.
        developer (Optional[str]): Developer or publisher of the APK.
        direct_download_url (Optional[str]): Direct link to download the APK, if available.
    """

    title: str
    url: str
    source: str  # e.g., "apkmirror", "apkpure", "google"
    description: Optional[str] = None
    version: Optional[str] = None
    developer: Optional[str] = None
    direct_download_url: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
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

    Provides a consistent interface for scraping APKs from different sources,
    including search functionality, download link retrieval, rate limiting, and
    session management.

    Attributes:
        timeout (int): Maximum time to wait for HTTP requests (in seconds).
        max_results (int): Maximum number of search results to return.
        rate_limit_delay (float): Delay (in seconds) between requests to avoid being blocked.
        user_agent (str): User-Agent string used in HTTP requests.
        headers (dict): HTTP headers including the User-Agent.
        session: Optional HTTP session object for persistent connections.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_results: int = 10,
        rate_limit_delay: float = 1.0,
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
    def search(self, query: str, captured_results: set) -> tuple[List[APKResult], set]:
        """Search for APKs matching a query.

        Args:
            query (str): The search term.
            captured_results (set): Set of already captured result titles to avoid duplicates.

        Returns:
            List[APKResult]: List of APK search results.\
            set: Set of already captured result titles.

        Raises:
            NotImplementedError: Must be implemented in subclasses.
        """
        raise NotImplementedError

    @abstractmethod
    def get_download_link(self, result: APKResult) -> Optional[str]:
        """Retrieve a direct download link from a search result.

        Args:
            result (APKResult): An APKResult object to extract the link from.

        Returns:
            Optional[str]: Direct download URL if available, otherwise None.

        Raises:
            NotImplementedError: Must be implemented in subclasses.
        """
        raise NotImplementedError

    @abstractmethod
    def search_and_download(
        self, query: str, captured_results: set
    ) -> tuple[List[APKResult], set]:
        """Search for APKs and retrieve their download links.

        Args:
            query (str): The search term.
            captured_results (set): Set of already captured result titles to avoid duplicates.

        Returns:
            List[APKResult]: List of APK search results with download links.
            set: Set of already captured result titles

        Raises:
            NotImplementedError: Must be implemented in subclasses.
        """
        raise NotImplementedError

    def _rate_limit(self):
        """Pause execution for `rate_limit_delay` seconds to prevent server blocking."""
        import time

        time.sleep(self.rate_limit_delay)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the HTTP session if it exists."""
        if self.session:
            self.session.close()
