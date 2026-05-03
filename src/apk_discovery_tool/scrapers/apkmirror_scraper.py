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

# APK MIrror scraper
from typing import List, Optional, Dict
from urllib.parse import quote_plus, urljoin
from scrapers.base_scraper import BaseAPKScraper
from scrapers.base_scraper import APKResult
import cloudscraper  # scraper to bypass cloudflare
from bs4 import BeautifulSoup
from requests import Response
import random
import time
import re


class APKMirrorScraper(BaseAPKScraper):
    """
    Scraper for APKMirror.com website utilising cloudscraper to bypass Cloudflare CAPTCHAs.
    """

    def __init__(
        self,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        max_results: int = 10,
    ):
        # Use default rate_limit_delay of 10 seconds as the lower limit from the base class
        super().__init__(timeout, user_agent, max_results)

        # Uses APK mirror for searching
        self.base_url = "https://www.apkmirror.com"
        self.search_url = f"{self.base_url}/?post_type=app_release&searchtype=apk&s="

        # Use cloudscraper to bypass Cloudflare bot protection
        self.scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "windows", "mobile": False}
        )

        # Cache the last search to avoid researching and making another request (susceptible to rate limit)
        self.cached_search = ""

        # Counter of how many APKs processed for current search
        self.apk_counter = 0

    def safe_get(self, url: str) -> Optional[Response]:
        """Request wrapper to prevent blocking"""
        retries = 5
        for attempt in range(retries):
            # use cloud scraper to send GET request to URL
            response = self.scraper.get(url, headers=self.headers, timeout=self.timeout)

            # If response successful sleep before returning response
            if response.status_code == 200:
                time.sleep(
                    random.uniform(self.rate_limit_delay, self.rate_limit_delay + 10)
                )
                return response

            if response.status_code == 429:
                # Exponential backoff since we got blocked
                wait = (2**attempt) * 60
                time.sleep(wait)
                continue

            response.raise_for_status()
        return None

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

        # Construct the search URL since we can pass the query through URL manipulation
        search_url = self.search_url + quote_plus(query)

        try:
            # If this is the first APK we don't have the app result page cached just yet so we need to cache it
            if self.apk_counter == 0:
                response = self.safe_get(search_url)

                if response is None:
                    print(f"Failed to retrieve a result for {query}..")
                    return None

                self.cached_search = response.text

            # Otherwise we have it cached, this way we optimise to decrease number of requests and possible throttling
            return self._parse_search_results(self.cached_search)

        except Exception as e:
            print(f"Error searching APKMirror: {e}")
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
        """Parses the HTML content of the search results page."""
        soup = BeautifulSoup(html, "html.parser")
        # Find all app rows
        app_rows = soup.find_all("div", {"class": "appRow"})

        # Ensure we haven't gone past all returned search results
        if self.apk_counter >= len(app_rows):
            print("No more app rows to process.")
            return None
        app_row = app_rows[self.apk_counter]
        try:
            # Parse the current row to find the download link
            result = self._parse_app_row(app_row)
            # Avoids duplicates based on base app name
            if result is not None:
                return result
        except Exception as e:
            print(f"Error parsing app row: {e}")

        return None

    def _parse_app_row(self, app_row) -> Optional[APKResult]:
        """Parses a single app row element to extract app details."""
        try:
            # Extract title and link
            title_elem = app_row.find("h5", {"class": "appRowTitle"})
            if not title_elem:
                return None

            title = title_elem.text.strip()
            link_elem = title_elem.find("a")
            if not link_elem:
                return None

            # Construct the URL for the app's page
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
            print(f"Error parsing app row details: {e}")
            return None

    def get_variant_link(self, APK_url: str) -> Optional[str]:
        """
        Get variant link from APK page.
        """
        # Step 1: Go to app page
        self._rate_limit()
        response = self.safe_get(APK_url)

        if response is None:
            print(f"Failed to get a response from {APK_url}...")
            return None

        # Step 2: Use BeautifulSoup to parse the page
        soup = BeautifulSoup(response.text, "html.parser")

        # Find the span child of the variant for the download link
        apk_spans = soup.select("svg.icon.tag-icon")

        apk_links = []
        # Find the link going through the variant's link for one particular variant of the APK
        for span in apk_spans:
            a = span.parent
            if a.name == "a" and "accent_color" in a.get("class", []):
                apk_links.append(a)

        if not apk_links:
            print("No variant links found")
            return None

        # Gets the first variant link since we don't mind which variant we get
        variant_page_url = urljoin(self.base_url, apk_links[0].get("href", ""))

        return variant_page_url

    def get_download_link(self, result: APKResult) -> Optional[str]:
        """
        Get direct download link for an APKMirror result.
        """
        if result.source != "apkmirror":
            return None

        try:
            apk_url = result.url

            # Step 3: Go to download page and find download button
            # Most apps require going though a variant link first but some don't so check both
            self._rate_limit()
            download_response = self.safe_get(apk_url)

            if download_response is None:
                print(f"Failed to get download page ({apk_url})...")
                return None

            # Parses the download page
            download_page_soup = BeautifulSoup(download_response.text, "html.parser")

            # find download button
            download_button = download_page_soup.find(
                "a",
                {
                    "class": "downloadButton",
                    "href": lambda href: (
                        href and "#downloads" not in href and href.startswith("/apk/")
                    ),
                },
            )

            # If there is no download button on the page, the page must have a variant link we must go through first
            if download_button is None:
                print("download button not found, attempting to get variant link...")
                apk_url = self.get_variant_link(result.url)

                if apk_url is None:
                    print(f"Failed to get the apk page ({result.url})...")
                    return None

                self._rate_limit()
                variant_response = self.safe_get(apk_url)

                # If no variant link there must be some issue
                if variant_response is None:
                    print(f"Failed to get the variant link page ({apk_url})...")
                    return None

                # Reparse the new response
                variant_soup = BeautifulSoup(variant_response.text, "html.parser")
                download_button = variant_soup.find("a", {"class": "downloadButton"})

                # If there is no download button on the variant page there is an issue
                if not download_button:
                    print("Download button still not found after getting variant link")
                    return None

            # Construct the URL used to get the link to the download page
            download_page_url = urljoin(self.base_url, download_button.get("href", ""))

            # Step 4: Go to download page to get final link to download the APK
            self._rate_limit()
            # download_headers = self.headers.copy()
            # download_headers["Referer"] = apk_url
            download_response = self.safe_get(download_page_url)

            if download_response is None:
                print(f"Failed to get the download page ({download_page_url})...")

            download_soup = BeautifulSoup(download_response.text, "html.parser")  # pyright: ignore

            # Find the actual download link by looking for an <a> tag with rel="nofollow" and href existing with download path
            download_link = download_soup.find(
                "a",
                {
                    "rel": "nofollow",
                    "data-google-interstitial": "false",
                    "href": lambda href: (
                        href and "/wp-content/themes/APKMirror/download.php" in href
                    ),
                },
            )

            if download_link:
                # If there is a download link construct it and return it
                direct_url = urljoin(self.base_url, download_link.get("href", ""))
                print(f"Found direct download URL: {direct_url}")
                return direct_url

            print("Direct download link not found")
            return None

        except Exception as e:
            print(f"Error getting download link: {e}")
            return None

    def search_and_download(
        self, query: str, captured_results: dict
    ) -> tuple[Optional[APKResult], dict]:
        """
        Search for an APK and get its download link in one call.
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
            # If extracted download link and fallback download link for this app then we don't need further copies
            existing_result = captured_results.get(base_name)
            if existing_result and existing_result.fallback_download_url:
                self.apk_counter += 1
                print("Duplicate found, skipping...")
                continue

            # Try to get download link if we have a result and don't have enough download links for APK
            download_link = self.get_download_link(result)

            # If there is no download link go to next APK
            if download_link is None:
                self.apk_counter += 1
                continue

            # If there is no existing entry for this result we add its direct download link
            if existing_result is None:
                result.direct_download_url = download_link
                captured_results[base_name] = result
                self.apk_counter += 1
                continue
            else:
                # Download and fallback URL found for this APK so no need to search further
                existing_result.fallback_download_url = download_link
                break

        self.apk_counter = 0
        return existing_result, captured_results
