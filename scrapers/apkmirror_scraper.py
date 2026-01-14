"""
APKMirror.com scraper implementation.
"""

from typing import List, Optional, Dict
from urllib.parse import quote_plus, urljoin
from scrapers.base_scraper import BaseAPKScraper
from scrapers.base_scraper import APKResult
import cloudscraper  # scraper to bypass cloudflare
from bs4 import BeautifulSoup
import logging


logger = logging.getLogger(__name__)


class APKMirrorScraper(BaseAPKScraper):
    """Scraper for APKMirror.com website utilising cloudscraper to bypass Cloudflare CAPTCHAs."""

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_results: int = 10,
        rate_limit_delay: float = 2.0,
    ):
        super().__init__(timeout, user_agent, max_results, rate_limit_delay)

        self.base_url = "https://www.apkmirror.com"
        self.search_url = f"{self.base_url}/?post_type=app_release&searchtype=apk&s="

        self.scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )

    def search(self, query: str) -> List[APKResult]:
        """
        Search APKMirror for APKs.

        Utilises quote_plus to encode the query string into a URL safe format. Then parses the response and returns the output.

        Args:
            query: Search query

        Returns:
            List of APKResult objects
        """

        # Apply rate limiting
        self._rate_limit()

        search_url = self.search_url + quote_plus(query)

        try:
            response = self.scraper.get(
                search_url, headers=self.headers, timeout=self.timeout
            )
            response.raise_for_status()

            return self._parse_search_results(response.text)

        except Exception as e:
            logger.error(f"Error searching APKMirror: {e}")
            return []

    def _parse_search_results(self, html: str) -> List[APKResult]:
        """Parses the HTML content of the search results page.

        Args:
            html (str): HTML content of the search results page.

        Returns:
            List[APKResult]: List of APKResult objects parsed from the page.
        """
        soup = BeautifulSoup(html, "html.parser")
        results = []
        # Find all app rows
        app_rows = soup.find_all("div", {"class": "appRow"})
        for app_row in app_rows[: self.max_results]:
            try:
                result = self._parse_app_row(app_row)
                if result:
                    results.append(result)
            except Exception as e:
                logger.debug(f"Error parsing app row: {e}")
                continue

        return results

    def _parse_app_row(self, app_row) -> Optional[APKResult]:
        """Parses a single app row element to extract app details.

        Args:
            app_row (bs4.element.Tag): BeautifulSoup tag representing an app row.

        Returns:
            Optional[APKResult]: APKResult object if parsing is successful; otherwise, None.
        """
        try:
            # Extract title and link
            title_elem = app_row.find("h5", {"class": "appRowTitle"})
            print(title_elem)
            if not title_elem:
                return None

            title = title_elem.text.strip()
            link_elem = title_elem.find("a")
            if not link_elem:
                return None

            app_url = urljoin(self.base_url, link_elem.get("href", ""))

            # Extract developer
            developer_elem = app_row.find("a", {"class": "byDeveloper"})
            developer = developer_elem.text.strip() if developer_elem else None

            return APKResult(
                title=title,
                url=app_url,
                source="apkmirror",
                developer=developer,
                version=version,
            )

        except Exception as e:
            logger.debug(f"Error parsing app row details: {e}")
            return None

    def get_download_link(self, result: APKResult) -> Optional[str]:
        """
        Get direct download link for an APKMirror result.

        Args:
            result: APKResult from search

        Returns:
            Direct download URL or None
        """
        if result.source != "apkmirror":
            return None

        try:
            # Step 1: Go to app page
            self._rate_limit()
            response = self.scraper.get(
                result.url, headers=self.headers, timeout=self.timeout
            )
            # raises exception for HTTP errors
            response.raise_for_status()

            # Step 2: Use BeautifulSoup to parse the page
            soup = BeautifulSoup(response.text, "html.parser")

            # Look for download variant links
            variant_links = soup.find_all("a", {"class": "accent_color"})

            if not variant_links:
                logger.warning("No variant links found")
                return None

            # Gets the first link
            variant_url = urljoin(self.base_url, variant_links[0].get("href", ""))

            # Step 3: Go to variant page to get download button
            self._rate_limit()
            variant_response = self.scraper.get(
                variant_url, headers=self.headers, timeout=self.timeout
            )
            variant_response.raise_for_status()

            # Parses the download page
            variant_soup = BeautifulSoup(variant_response.text, "html.parser")

            # Find download button
            download_button = variant_soup.find("a", {"class": "downloadButton"})
            if not download_button:
                logger.warning("Download button not found")
                return None

            download_page_url = urljoin(self.base_url, download_button.get("href", ""))

            # Step 4: Go to download page to get final link
            self._rate_limit()
            download_response = self.scraper.get(
                download_page_url, headers=self.headers, timeout=self.timeout
            )
            download_response.raise_for_status()

            download_soup = BeautifulSoup(download_response.text, "html.parser")

            # Find the actual download link
            download_link = download_soup.find(
                "a",
                {
                    "rel": "nofollow",
                    "data-google-interstitial": "false",
                    "href": lambda href: href
                    and "/wp-content/themes/APKMirror/download.php" in href,
                },
            )

            if download_link:
                direct_url = urljoin(self.base_url, download_link.get("href", ""))
                logger.info(f"Found direct download URL: {direct_url}")
                return direct_url

            logger.warning("Direct download link not found")
            return None

        except Exception as e:
            logger.error(f"Error getting download link: {e}")
            return None

    def search_and_download(self, query: str) -> List[APKResult]:
        """
        Search and get download links in one call.

        Args:
            query: Search query

        Returns:
            List of dicts with search results and download links
        """
        results = self.search(query)

        enhanced_results = []
        for result in results:
            download_link = self.get_download_link(result)
            result.direct_download_url = download_link
            enhanced_results.append(result)

        return enhanced_results
