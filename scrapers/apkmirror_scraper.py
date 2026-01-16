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
import re


logger = logging.getLogger(__name__)


class APKMirrorScraper(BaseAPKScraper):
    """
    Scraper for APKMirror.com website utilising cloudscraper to bypass Cloudflare CAPTCHAs.

    Attributes:
        timeout (int): Timeout for HTTP requests in seconds.
        user_agent (Optional[str]): Custom User-Agent string for HTTP requests.
        max_results (int): Maximum number of search results to return.
        rate_limit_delay (float): Delay between requests to avoid rate limiting.
    """

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

    def search(self, query: str, captured_results: set) -> tuple[List[APKResult], set]:
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

            return self._parse_search_results(response.text, captured_results)

        except Exception as e:
            logger.error(f"Error searching APKMirror: {e}")
            return [], set()

    def _extract_base_name(self, title: str) -> str:
        """
        Extracts the base app name by removing version numbers at the end.

        Examples:
            "ABC 6.4.2" -> "ABC"
            "EFG 5.23.4" -> "EFG"
        """
        parts = title.strip().split()
        # If last part looks like a version, remove it
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*\d[A-Za-z0-9.\-]*", parts[-1]):
            parts = parts[:-1]
        return " ".join(parts)

    def _parse_search_results(
        self, html: str, captured_results: set
    ) -> tuple[List[APKResult], set]:
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
                # Avoids duplicates based on base app name
                if result is not None:
                    base_name = self._extract_base_name(result.title).lower()
                    if base_name not in captured_results:
                        results.append(result)
                        captured_results.add(
                            self._extract_base_name(result.title).lower()
                        )
            except Exception as e:
                logger.debug(f"Error parsing app row: {e}")
                continue

        return results, captured_results

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
            if not title_elem:
                return None

            title = title_elem.text.strip()
            link_elem = title_elem.find("a")
            if not link_elem:
                return None

            app_url = urljoin(self.base_url, link_elem.get("href", ""))

            # Extract version by taking the last word of the title and ensuring it consists of numbers and periods
            version = (
                title.strip().split()[-1]
                if re.fullmatch(r"\d+(?:\.\d+)+", title.strip().split()[-1])
                else None
            )

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

            # Find the span child of the variant for the download link
            apk_spans = soup.find_all("svg", class_=["icon", "tag-icon"])

            apk_links = []
            for span in apk_spans:
                row = span.parent
                a = row.find("a", class_="accent_color", href=True)
                if a:
                    apk_links.append(a)

            if not apk_links:
                logger.warning("No variant links found")
                return None

            # Gets the first link
            apk_url = urljoin(self.base_url, apk_links[0].get("href", ""))

            # Step 3: Go to variant page to get download button
            self._rate_limit()
            variant_response = self.scraper.get(
                apk_url, headers=self.headers, timeout=self.timeout
            )
            variant_response.raise_for_status()

            # Parses the download page
            variant_soup = BeautifulSoup(variant_response.text, "html.parser")

            # Find download button
            download_button = variant_soup.find("a", {"class": "downloadButton"})
            if not download_button:
                logger.warning("Download button not found")
                print(apk_url)
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

    def search_and_download(
        self, query: str, captured_results: set
    ) -> tuple[List[APKResult], set]:
        """
        Search and get download links in one call.

        Args:
            query: Search query

        Returns:
            List of dicts with search results and download links
        """
        results, captured_results = self.search(query, captured_results)

        enhanced_results = []
        for result in results:
            download_link = self.get_download_link(result)
            result.direct_download_url = download_link
            enhanced_results.append(result)

        return enhanced_results, captured_results
