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
#
# main.py
import os
import json
import time
import argparse
import requests
from tqdm import tqdm
from dotenv import load_dotenv

from query_snowballer.snowballer import QuerySnowballer
from query_provider.google_provider import GoogleQueryFinder
from apk_finder.google_cse_client import GoogleAPKSearcher
from scrapers.apkmirror_scraper import APKMirrorScraper
from scrapers.apkmirror_scraper import APKResult


# from downloaders.downloader import Downloader
from downloaders.selenium_downloader import SeleniumDownloader
from downloaders.downloader import Downloader
from downloaders.cleaner import Cleaner
from utils.config import (
    GOOGLE_API_KEY,
    GOOGLE_SEARCH_ENGINE_ID,
    EXPANDED_QUERIES_FILE,
    SEARCH_RESULTS_FILE,
    DOWNLOAD_DIRECTORY,
    DIRECT_DOWNLOADS_FILE,
    PROGRESS_FILE,
    TEMP_DOWNLOADS_FILE,
)

load_dotenv()


def check_constants():
    """Check if essential constants are set."""
    missing = []
    if not isinstance(GOOGLE_API_KEY, str):
        missing.append("GOOGLE_API_KEY")
    if not isinstance(GOOGLE_SEARCH_ENGINE_ID, str):
        missing.append("GOOGLE_SEARCH_ENGINE_ID")
    if not isinstance(DOWNLOAD_DIRECTORY, str):
        missing.append("DOWNLOAD_DIRECTORY")
    if not isinstance(EXPANDED_QUERIES_FILE, str):
        missing.append("EXPANDED_QUERIES_FILE")
    if not isinstance(SEARCH_RESULTS_FILE, str):
        missing.append("SEARCH_RESULTS_FILE")
    if not isinstance(DIRECT_DOWNLOADS_FILE, str):
        missing.append("DIRECT_DOWNLOADS_FILE")
    if not isinstance(PROGRESS_FILE, str):
        missing.append("PROGRESS_FILE")
    if not isinstance(TEMP_DOWNLOADS_FILE, str):
        missing.append("TEMP_DOWNLOAD_FILE")
    if missing:
        raise ValueError(f"Missing or invalid constants: {', '.join(missing)}")


def get_top_apple_apps(limit=75):
    """Fetches top free iOS app titles using Apple's RSS feed because google play store scraper doesn't have a list of top apps we can access"""
    print(f"Fetching top {limit} Apple apps...")
    url = f"https://itunes.apple.com/us/rss/topfreeapplications/limit={limit}/json"
    try:
        response = requests.get(url)
        data = response.json()
        apps = data["feed"]["entry"]
        # Extract the titles
        return [app["im:name"]["label"] for app in apps]
    except Exception as e:
        print(f"Error fetching Apple apps: {e}")
        return []


def find_and_save_queries():
    """Expand seed queries and save to file."""
    seed_queries = [
        "parental control app",
        "kids tracker app",
        "track my wife",  # Almansoori
        "family locator",  # In chatterjee's paper
        "find my phone",  # Chatterjee
        "mobile monitoring app",
        "track my girlfriend's phone without them knowing",
        "how to catch my cheating spouse",  # Chatterjee
        "track my husband's phone without them knowing",  # Chatterjee
        "read SMS from another phone",  # Chatterjee
        "how can I read my wife's texts",  # Chatterjee
        "phone spy on husband",  # Chatterjee
        "see who bf is texting without him knowing",  # Chatterjee
        "how to catch a cheating spouse with his cell phone",  # Chatterjee
        "track wife's location",  # Almansoori
        "app to track girlfriend",  # Almansoori
        "track your husband",  # Almansoori
        "track my spouse",  # Almansoori
        "track my couple",  # Almansoory
        "SMS tracker",  # Chatterjee
        "Cereberus",  # Chatterjee
        "Mspy",  # Chatterjee
        "Maps",
    ]

    provider = GoogleQueryFinder()
    snowballer = QuerySnowballer(
        provider=provider, max_depth=5, max_queries=200, per_query_limit=10
    )

    all_queries = snowballer.expand(seed_queries)
    # Add top 75 apple apps
    all_queries.extend(get_top_apple_apps(75))

    print("Expanded Queries:")
    for q in all_queries:
        print("-", q)

    os.makedirs(os.path.dirname(EXPANDED_QUERIES_FILE), exist_ok=True)  # pyright: ignore
    with open(EXPANDED_QUERIES_FILE, "w") as f:  # pyright: ignore
        json.dump(all_queries, f, indent=2)

    print(f"\nSaved expanded queries to {EXPANDED_QUERIES_FILE}")
    return all_queries


def search_and_save_apks(queries, max_queries=10):
    """Search Google Custom Search for APKs and save results."""
    apk_searcher = GoogleAPKSearcher(GOOGLE_API_KEY, GOOGLE_SEARCH_ENGINE_ID)  # pyright: ignore
    all_results = []

    for query in tqdm(queries[:max_queries], desc="Searching APKs"):
        time.sleep(3)
        try:
            # In case internet crashes or the API runs out of searches
            results = apk_searcher.search_apks(query, 5)
            all_results.extend(results)
        except Exception as e:
            print(f"Error searching for query: {query}\nException: {e}")
            continue

    # Remove duplicates by title and clean text
    seen_titles = set()
    filtered = []
    for r in all_results:
        title = clean_text(r["title"].strip().lower())
        snippet = clean_text(r.get("snippet", ""))
        if title not in seen_titles:
            seen_titles.add(title)
            filtered.append({"title": title, "snippet": snippet})

    os.makedirs(os.path.dirname(SEARCH_RESULTS_FILE), exist_ok=True)  # pyright: ignore
    with open(SEARCH_RESULTS_FILE, "w") as f:  # pyright: ignore
        json.dump(filtered, f, indent=2)

    print(f"\nSaved search results to {SEARCH_RESULTS_FILE}")
    return filtered


def clean_text(text):
    """Remove problematic control characters from text."""
    if not text:
        return ""
    # Remove carriage returns, newlines, tabs
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # Collapse multiple spaces
    text = " ".join(text.split())
    return text


def load_json(file_path):
    """Load JSON data from file."""
    with open(file_path, "r") as f:
        return json.load(f)


def get_downloader(downloader_type, download_dir):
    """Factory function to return the appropriate downloader instance."""
    if downloader_type == "selenium":
        return SeleniumDownloader(download_dir=download_dir)
    # Default to basic downloader
    else:
        return Downloader(download_dir=download_dir)


def save_apk_downloads_to_file(apk_downloads, file_path):
    """Save APK download information to JSON file."""
    apk_data = []

    # Read the old download data so we can append to the file
    if os.path.exists(file_path):
        try:
            with open(file_path, "r") as f:
                apk_data = json.load(f)
        except Exception as e:
            print(f"Warning: Could not read existing file, starting fresh: {e}")

    for apk in apk_downloads:
        apk_data.append(
            {
                "title": apk.title,
                "url": apk.url,
                "source": apk.source,
                "version": apk.version,
                "developer": apk.developer,
                "direct_download_url": apk.direct_download_url,
                "fallback_download_url": apk.fallback_download_url,
            }
        )

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(apk_data, f, indent=2)

    print(f"\nSaved {len(apk_data)} APK downloads to {file_path}")
    return apk_data


def load_captured_results():
    """Load captured results from file for fault tolerance."""
    captured_file = os.path.join(
        os.path.dirname(PROGRESS_FILE),  # pyright: ignore
        "captured_results.json",
    )
    if os.path.exists(captured_file):
        try:
            with open(captured_file, "r") as f:
                data = json.load(f)
                # Reconstruct APKResult objects from dicts
                captured_results = {}
                for key, value in data.items():
                    apk = APKResult(
                        title=value["title"],
                        url=value["url"],
                        source=value["source"],
                        version=value["version"],
                        developer=value["developer"],
                        direct_download_url=value.get("direct_download_url"),
                        fallback_download_url=value.get("fallback_download_url"),
                    )
                    captured_results[key] = apk
                return captured_results
        except Exception as e:
            print(f"Error loading captured results: {e}")
    return {}


def save_captured_results(captured_results: dict):
    """Save captured results to disk for fault tolerance."""
    captured_file = os.path.join(
        os.path.dirname(PROGRESS_FILE),  # pyright: ignore
        "captured_results.json",
    )
    # Convert APKResult objects todicts
    dictionary = {}
    for key, apk in captured_results.items():
        dictionary[key] = apk.to_dict()

    os.makedirs(os.path.dirname(captured_file), exist_ok=True)
    with open(captured_file, "w") as f:
        json.dump(dictionary, f, indent=2)


def download_apks_from_file(file_path, download_dir, downloader):
    """Download APKs from a saved JSON file."""
    if not os.path.exists(file_path):
        print(f"Error: APK downloads file not found at {file_path}")
        print("Run with -a --scrape-apkmirror first to create this file")
        return

    apk_data = load_json(file_path)
    print(f"Loaded {len(apk_data)} APK downloads from {file_path}")

    if not apk_data:
        print("No APK downloads found in the file")
        return

    try:
        for apk_info in tqdm(apk_data, desc="Downloading APKs"):
            if apk_info.get("direct_download_url"):
                # Use title as filename or generate from URL
                # filename = apk_info.get("title")
                download_url = apk_info["direct_download_url"]
                fallback_url = apk_info.get("fallback_download_url")

                print(f"\nDownloading: {apk_info.get('title', 'Unknown')}")
                print(f"URL: {download_url}")
                print(f"Fallback URL: {fallback_url}")

                try:
                    file_path = downloader.download_file(
                        download_url, apk_info.get("title")
                    )
                    print(f"Downloaded: {file_path}")
                except Exception as e:
                    print(f"Failed to download: {e}")
                    if fallback_url:
                        print("Attempting fallback URL...")
                        try:
                            file_path = downloader.download_file(
                                fallback_url, apk_info.get("title")
                            )
                            print(f"Downloaded via fallback: {file_path}")
                        except Exception as e2:
                            print(f"Fallback download failed: {e2}")
    finally:
        downloader.close()


def chunk_queries(queries: list[str], size: int):
    """Yield successive n-sized chunks from queries."""
    for i in range(0, len(queries), size):
        yield queries[i : i + size]


def load_finished() -> list[str]:
    """Load app files that we have finished scraping and downloading"""
    if os.path.exists(PROGRESS_FILE):  #  pyright: ignore
        with open(PROGRESS_FILE, "r") as f:  #  pyright: ignore
            return json.load(f)
    return []


def save_finished(title: str):
    finished = load_finished()
    if title not in finished:
        finished.append(title)
        with open(PROGRESS_FILE, "w") as f:  #  pyright: ignore
            json.dump(finished, f)


def already_downloaded(apk, download_dir: str) -> bool:
    """
    Returns True if an APK with same title + version
    already exists in download directory.
    """
    expected_fragment = apk.title.lower()

    print(f"Looking for file {expected_fragment} in {download_dir}... Not found.")

    for file in os.listdir(download_dir):
        if file.lower().endswith((".apk", ".apkm")):
            if expected_fragment in file.lower():
                return True

    return False


def main():
    check_constants()

    parser = argparse.ArgumentParser(description="APK Discovery Tool")
    parser.add_argument(
        "-g",
        "--generate-queries",
        action="store_true",
        help="Expand seed queries and save to file",
    )
    parser.add_argument(
        "-l",
        "--load-queries",
        action="store_true",
        help="Load expanded queries from file",
    )
    parser.add_argument(
        "-s", "--search-apks", action="store_true", help="Search for APKs using queries"
    )
    parser.add_argument(
        "-r",
        "--load-results",
        action="store_true",
        help="Load APK search results from file (use if you have ran main with -s flag before)",
    )
    parser.add_argument(
        "-a",
        "--scrape-apkmirror",
        action="store_true",
        help="Scrape APKMirror for APK download links",
    )
    parser.add_argument(
        "-b",
        "--batch",
        action="store_true",
        help="Scrapes and saves applications in batches of 20, saving progress with each batch",
    )
    parser.add_argument(
        "-sd",
        "--save-downloads",
        action="store_true",
        help="Save scraped APK download links to file (use with -a)",
    )
    parser.add_argument(
        "-dd",
        "--direct-download",
        action="store_true",
        help="Directly download APKs after scraping (use with -a)",
    )
    parser.add_argument(
        "-ld",
        "--load-and-download",
        choices=["batch", "all"],
        help="Load APK downloads from file and download them (use if you have run main with (-a and -sd) or (-b) flags before). 'batch' to download from temp batch file, 'all' to download from the cumulative direct downloads file",
    )

    parser.add_argument(
        "-c",
        "--cleanup",
        action="store_true",
        help="Extact APKs from APKMs and remove APKMs and other non-APK file extensions (use with -dd or -ld flags)",
    )

    parser.add_argument(
        "--downloader",
        choices=["basic", "selenium"],
        default="basic",
        help="'basic' for cloudscraper downloader (default), 'selenium' for Selenium downloader",
    )

    args = parser.parse_args()

    # Initialize variables
    queries = []
    filtered = []
    all_apk_downloads = []

    # If no flags are provided, default to loading queries and results
    if not any(vars(args).values()):
        args.load_queries = True
        args.load_results = True
        print(
            "No flags provided. Defaulting to loading queries and search results from files.\n"
        )

    # Step 1: Queries
    if args.generate_queries:
        queries = find_and_save_queries()
    elif args.load_queries:
        queries = load_json(EXPANDED_QUERIES_FILE)
        print(f"Loaded {len(queries)} queries from {EXPANDED_QUERIES_FILE}")

    # Step 2: APK Search
    if args.search_apks and queries:
        filtered = search_and_save_apks(queries, len(queries))
    elif args.load_results:
        filtered = load_json(SEARCH_RESULTS_FILE)
        print(f"Loaded {len(filtered)} APK search results from {SEARCH_RESULTS_FILE}")

    # Step 3: Print search results
    if filtered:
        print(f"\n{'=' * 50}")
        print(f"SEARCH RESULTS ({len(filtered)} items):")
        print(f"{'=' * 50}")
        for i in filtered:
            print(f"\nTitle: {i['title']} \nSnippet: {i['snippet'][:100]}...")

    # Step 4: APKMirror scraping
    if args.scrape_apkmirror and filtered:
        scraper = APKMirrorScraper()
        all_apk_downloads = []
        captured_results = {}

        print(f"\n{'=' * 50}")
        print("SCRAPING APKMIRROR")
        print(f"{'=' * 50}")

        for result in tqdm(filtered, desc="Obtaining APK info from APKMirror"):
            captured_results = scraper.search_and_download(
                result["title"], captured_results
            )

            # Clear the cached search before the next search to prevent memory bloat
            scraper.cached_search = ""

        for apk in captured_results.values():
            if apk.direct_download_url and not already_downloaded(
                apk,
                DOWNLOAD_DIRECTORY,  # pyright: ignore
            ):
                all_apk_downloads.append(apk)

        print(f"\nScraping complete. Found {len(all_apk_downloads)} APKs.")

        # Display scraped APKs
        for i, apk in enumerate(all_apk_downloads, 1):
            print(f"\nAPK {i}:\n{apk}")

        # Save downloads to file
        if args.save_downloads and all_apk_downloads:
            save_apk_downloads_to_file(all_apk_downloads, DIRECT_DOWNLOADS_FILE)

        # Direct download after scraping
        if args.direct_download and all_apk_downloads:
            print(f"\n{'=' * 50}")
            print("DIRECT DOWNLOAD")
            print(f"{'=' * 50}")
            downloader = get_downloader(args.downloader, DOWNLOAD_DIRECTORY)  # pyright: ignore
            try:
                for apk in all_apk_downloads:
                    if apk.direct_download_url:
                        filename = f"{apk.title}"
                        print(f"\nDownloading: {filename}")
                        try:
                            file_path = downloader.download_file(
                                apk.direct_download_url, apk.title
                            )
                            print(f"Downloaded: {file_path}")
                            # Move to next APK
                            continue
                        except Exception as e:
                            print(f"Failed: {e}")

                    if apk.fallback_download_url:
                        print("Attempting fallback URL...")
                        try:
                            file_path = downloader.download_file(
                                apk.fallback_download_url, apk.title
                            )
                            print(f"Downloaded via fallback: {file_path}")
                        except Exception as e:
                            print(f"Fallback failed: {e}")
            finally:
                downloader.close()

    # Step 4b: Batching scraping and downloads
    if args.batch and filtered:
        scraper = APKMirrorScraper()
        captured_results = load_captured_results()

        downloaded = load_finished()
        print("STARTING BATCHED SCRAPING AND DOWNLOADING")

        BATCH_SIZE = 20

        batches = chunk_queries(filtered, BATCH_SIZE)
        numbered_batches = enumerate(batches, start=1)

        for i, batch_items in numbered_batches:
            print(
                f"\n> PROCESSING BATCH {i} (Items {((i - 1) * BATCH_SIZE) + 1} to {i * BATCH_SIZE})"
            )

            newly_fin = []
            batch_apks = []

            captured_before = set(captured_results.keys())

            for result in tqdm(batch_items, desc=f"Scraping Batch {i}"):
                title = result["title"]  # pyright: ignore

                # If we have seen the title query before and downloaded it we should skip
                if title in downloaded:
                    continue

                try:
                    captured_results = scraper.search_and_download(
                        title, captured_results
                    )

                    # Mark this query as downloaded for the next iteration since we don't load from the file on each iteration. No problem here since if the batch fails, we will just reattempt this whole batch and downloaded is lost to memory
                    downloaded.append(title)
                    # Keep track of queries that have been finished in this batch
                    newly_fin.append(title)

                except Exception as e:
                    print(f"Error processing {title}: {e}")
                    continue

            # Remove the temporary downloads file if it exists from the previous batch
            if os.path.exists(TEMP_DOWNLOADS_FILE):  # pyright: ignore
                os.remove(TEMP_DOWNLOADS_FILE)  # pyright: ignore

            # Find all new captured results from this batch
            captured_after = set(captured_results.keys())
            new_captured_keys = captured_after - captured_before

            # Add the new APKs into a list to be downloaded
            for key in new_captured_keys:
                apk = captured_results[key]
                if (
                    not already_downloaded(apk, DOWNLOAD_DIRECTORY)  # pyright: ignore
                    and apk.direct_download_url
                ):
                    batch_apks.append(apk)

            if batch_apks:
                # Save the batched APKs to the direct downloads file (cumulative) and temp downloads file (current batch only) as well as the captured results for fault tolerance, then download the APKs from the current batch
                # Direct download file is not needed by program just for record sake
                save_apk_downloads_to_file(batch_apks, DIRECT_DOWNLOADS_FILE)
                # Temp download file is needed to keep track of what to download for current batch
                save_apk_downloads_to_file(batch_apks, TEMP_DOWNLOADS_FILE)

                # Save all captured results
                save_captured_results(captured_results)
                downloader = get_downloader(args.downloader, DOWNLOAD_DIRECTORY)  # pyright: ignore
                download_apks_from_file(
                    TEMP_DOWNLOADS_FILE, DOWNLOAD_DIRECTORY, downloader
                )

            for title in newly_fin:
                # Only save the title after download is done, otherwise we redownload
                save_finished(title)

            print(f"Batch {i} completed.")

    # Step 5: Load from file and download
    if args.load_and_download:
        if not DOWNLOAD_DIRECTORY:
            print("Error: DOWNLOAD_DIRECTORY not configured in config.py")
            return
        downloader = get_downloader(args.downloader, DOWNLOAD_DIRECTORY)  # pyright: ignore
        if args.load_and_download == "batch":
            download_apks_from_file(TEMP_DOWNLOADS_FILE, DOWNLOAD_DIRECTORY, downloader)
        else:
            download_apks_from_file(
                DIRECT_DOWNLOADS_FILE, DOWNLOAD_DIRECTORY, downloader
            )

    # Step 6: Cleanup downloaded files
    if args.cleanup:
        print("WARNING: This will:")
        print("  1. Extract base.apk from APKM files")
        print("  2. Rename them as [original_name]_base.apk")
        print("  3. DELETE the original APKM files")
        print("  4. DELETE all non-APK files")
        print(f"\nTarget directory: {DOWNLOAD_DIRECTORY}")

        response = input("\nContinue? (yes/no): ").strip().lower()
        if response in ["y", "yes"]:
            Cleaner.process_directory(DOWNLOAD_DIRECTORY)  # pyright: ignore
        else:
            print("Operation cancelled.")


if __name__ == "__main__":
    main()
