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
        cached_search (str): Cached HTML content of the last search results page.
        apk_counter (int): Counter to track the number the current app row, if apk download link is not found.
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
        self.cached_search = ""
        self.apk_counter = 0

    def search(self, query: str) -> Optional[APKResult]:
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
        print(f"Query: {query}")

        search_url = self.search_url + quote_plus(query)

        try:
            if self.apk_counter == 0:
                response = self.scraper.get(
                    search_url, headers=self.headers, timeout=self.timeout
                )
                response.raise_for_status()
                self.cached_search = response.text

            return self._parse_search_results(self.cached_search)

        except Exception as e:
            logger.error(f"Error searching APKMirror: {e}")
            return None

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

    def _parse_search_results(self, html: str) -> Optional[APKResult]:
        """Parses the HTML content of the search results page.

        Args:
            html (str): HTML content of the search results page.

        Returns:
            List[APKResult]: List of APKResult objects parsed from the page.
        """
        soup = BeautifulSoup(html, "html.parser")
        # Find all app rows
        app_rows = soup.find_all("div", {"class": "appRow"})

        if self.apk_counter >= len(app_rows):
            print("No more app rows to process.")
            return None
        app_row = app_rows[self.apk_counter]
        try:
            result = self._parse_app_row(app_row)
            # Avoids duplicates based on base app name
            if result is not None:
                return result
        except Exception as e:
            logger.debug(f"Error parsing app row: {e}")

        return None

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

    def get_variant_link(self, APK_url: str) -> Optional[str]:
        """
        Get variant link from APK page.

        Args:
            APK_url: URL of the APK page
        Returns:
            Variant page URL or None
        """
        # Step 1: Go to app page
        self._rate_limit()
        response = self.scraper.get(APK_url, headers=self.headers, timeout=self.timeout)
        # raises exception for HTTP errors
        response.raise_for_status()

        # Step 2: Use BeautifulSoup to parse the page
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the span child of the variant for the download link
        apk_spans = soup.select("svg.icon.tag-icon")

        apk_links = []
        for span in apk_spans:
            a = span.parent
            if a.name == "a" and "accent_color" in a.get("class", []):
                apk_links.append(a)

        if not apk_links:
            logger.warning("No variant links found")
            return None

        # Gets the first link
        variant_page_url = urljoin(self.base_url, apk_links[0].get("href", ""))

        return variant_page_url

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
            apk_url = result.url

            # Step 3: Go to download page and find download button
            self._rate_limit()
            download_response = self.scraper.get(
                apk_url, headers=self.headers, timeout=self.timeout
            )
            download_response.raise_for_status()

            # Parses the download page
            download_page_soup = BeautifulSoup(download_response.text, "html.parser")

            # find download button
            download_button = download_page_soup.find(
                "a",
                {
                    "class": "downloadButton",
                    "href": lambda href: href
                    and "#downloads" not in href
                    and href.startswith("/apk/"),
                },
            )

            if download_button is None:
                logger.warning(
                    "download button not found, attempting to get variant link..."
                )
                apk_url = self.get_variant_link(result.url)

                self._rate_limit()
                variant_response = self.scraper.get(
                    apk_url, headers=self.headers, timeout=self.timeout
                )
                variant_response.raise_for_status()

                # Re-parse the new response
                variant_soup = BeautifulSoup(variant_response.text, "html.parser")
                download_button = variant_soup.find("a", {"class": "downloadButton"})

                if not download_button:
                    logger.error(
                        "Download button still not found after getting variant link"
                    )
                    return None

            download_page_url = urljoin(self.base_url, download_button.get("href", ""))

            # Step 4: Go to download page to get final link
            self._rate_limit()
            download_headers = self.headers.copy()
            download_headers["Referer"] = apk_url
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
        self, query: str, captured_results: dict
    ) -> tuple[Optional[APKResult], dict]:
        """
        Search for an APK and get its download link in one call.

        Args:
            query: Search query
            captured_results: Dict of already captured results to avoid duplicates

        Returns:
            Tuple containing:
                - APKResult with download link, or None if not found
                - Updated captured_results dictionary
        """
        result: Optional[APKResult] = None

        while True:
            if self.apk_counter >= self.max_results:
                print("Reached maximum number of attempts, stopping search.")
                self.apk_counter = 0
                return None, captured_results

            result = self.search(query)

            # Stop if search returned nothing
            if result is None:
                print("No result found.")
                self.apk_counter = 0
                return None, captured_results

            base_name = self._extract_base_name(result.title).lower()
            # If extracted download link and backup for this app then we don't need further copies
            existing_result = captured_results.get(base_name)
            if existing_result and existing_result.fallback_download_url:
                self.apk_counter += 1
                print("Duplicate found, skipping...")
                continue

            # Try to get download link if we have a result and don't have enough download links for APK
            download_link = self.get_download_link(result)

            if download_link is None:
                self.apk_counter += 1
                continue

            if existing_result is None:
                result.direct_download_url = download_link
                captured_results[base_name] = result
                self.apk_counter += 1
                continue
            else:
                # Download and fallback URL found no need to search further
                existing_result.fallback_download_url = download_link
                break

        self.apk_counter = 0
        return existing_result, captured_results
