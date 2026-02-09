# main.py
import os
import json
import time
import argparse
from tqdm import tqdm
from dotenv import load_dotenv

from query_snowballer.snowballer import QuerySnowballer
from query_provider.google_provider import GoogleQueryFinder
from apk_finder.google_cse_client import GoogleAPKSearcher
from scrapers.apkmirror_scraper import APKMirrorScraper
from downloaders.downloader import Downloader
from downloaders.cleaner import Cleaner
from utils.config import (
    GOOGLE_API_KEY,
    GOOGLE_SEARCH_ENGINE_ID,
    EXPANDED_QUERIES_FILE,
    SEARCH_RESULTS_FILE,
    DOWNLOAD_DIRECTORY,
    DIRECT_DOWNLOADS_FILE,
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
    if missing:
        print(f"Error: Missing configuration for {', '.join(missing)} in config.py")
        exit(1)


def find_and_save_queries():
    """Expand seed queries and save to file."""
    seed_queries = [
        "parental control app",
        "kids tracker app",
        "track my wife",
        "family locator",
        "find my phone",
        "mobile monitoring app",
    ]

    provider = GoogleQueryFinder()
    snowballer = QuerySnowballer(
        provider=provider, max_depth=2, max_queries=50, per_query_limit=10
    )

    all_queries = snowballer.expand(seed_queries)

    print("Expanded Queries:")
    for q in all_queries:
        print("-", q)

    os.makedirs(os.path.dirname(EXPANDED_QUERIES_FILE), exist_ok=True)
    with open(EXPANDED_QUERIES_FILE, "w") as f:
        json.dump(all_queries, f, indent=2)

    print(f"\nSaved expanded queries to {EXPANDED_QUERIES_FILE}")
    return all_queries


def search_and_save_apks(queries, max_queries=10):
    """Search Google Custom Search for APKs and save results."""
    apk_searcher = GoogleAPKSearcher(GOOGLE_API_KEY, GOOGLE_SEARCH_ENGINE_ID)
    all_results = []

    for query in tqdm(queries[:max_queries], desc="Searching APKs"):
        time.sleep(3)
        results = apk_searcher.search_apks(query, 5)
        all_results.extend(results)

    # Remove duplicates by title and clean text
    seen_titles = set()
    filtered = []
    for r in all_results:
        title = clean_text(r["title"].strip().lower())
        snippet = clean_text(r.get("snippet", ""))
        if title not in seen_titles:
            seen_titles.add(title)
            filtered.append({"title": title, "snippet": snippet})

    os.makedirs(os.path.dirname(SEARCH_RESULTS_FILE), exist_ok=True)
    with open(SEARCH_RESULTS_FILE, "w") as f:
        json.dump(filtered, f, indent=2)

    print(f"\nSaved search results to {SEARCH_RESULTS_FILE}")
    return filtered


def clean_text(text):
    """Remove problematic control characters from text."""
    if not text:
        return ""
    # Remove carriage returns, newlines, tabs
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # Optional: collapse multiple spaces
    text = " ".join(text.split())
    return text


def load_json(file_path):
    """Load JSON data from file."""
    with open(file_path, "r") as f:
        return json.load(f)


def save_apk_downloads_to_file(apk_downloads, file_path):
    """Save APK download information to JSON file."""
    apk_data = []
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


def download_apks_from_file(file_path, download_dir):
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

    downloader = Downloader(download_dir=download_dir)

    for apk_info in tqdm(apk_data, desc="Downloading APKs"):
        if apk_info.get("direct_download_url"):
            # Use title as filename or generate from URL
            filename = apk_info.get("title")
            download_url = apk_info["direct_download_url"]
            fallback_url = apk_info.get("fallback_download_url")

            print(f"\nDownloading: {apk_info.get('title', 'Unknown')}")
            print(f"URL: {download_url}")
            print(f"Fallback URL: {fallback_url}")

            try:
                downloader.download_file(download_url, filename)
                print(f"Downloaded: {filename}")
            except Exception as e:
                print(f"Failed to download: {e}")
                if fallback_url:
                    print("Attempting fallback URL...")
                    try:
                        downloader.download_file(fallback_url, filename)
                        print(f"Downloaded via fallback: {filename}")
                    except Exception as e2:
                        print(f"Fallback download failed: {e2}")


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
        action="store_true",
        help="Load APK downloads from file and download them (use if you have run main with -a and -sd flags before)",
    )

    parser.add_argument(
        "-c",
        "--cleanup",
        action="store_true",
        help="Extact APKs from APKMs and remove APKMs and other non-APK file extensions (use with -dd or -ld flags)",
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
        filtered = search_and_save_apks(queries)
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
            apk, captured_results = scraper.search_and_download(
                result["title"], captured_results
            )
            if apk is not None:
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
            downloader = Downloader(download_dir=DOWNLOAD_DIRECTORY)
            for apk in all_apk_downloads:
                if apk.direct_download_url:
                    filename = f"{apk.title}"
                    print(f"\nDownloading: {filename}")
                    try:
                        downloader.download_file(apk.direct_download_url, filename)
                        print(f"Downloaded: {filename}")
                    except Exception as e:
                        print(f"Failed: {e}")

    # Step 5: Load from file and download
    if args.load_and_download:
        if not DOWNLOAD_DIRECTORY:
            print("Error: DOWNLOAD_DIRECTORY not configured in config.py")
            return
        download_apks_from_file(DIRECT_DOWNLOADS_FILE, DOWNLOAD_DIRECTORY)

    # Step 6: Cleanup downloaded files
    if args.cleanup:
        print(f"WARNING: This will:")
        print(f"  1. Extract base.apk from APKM files")
        print(f"  2. Rename them as [original_name]_base.apk")
        print(f"  3. DELETE the original APKM files")
        print(f"  4. DELETE all non-APK files")
        print(f"\nTarget directory: {DOWNLOAD_DIRECTORY}")

        response = input("\nContinue? (yes/no): ").strip().lower()
        if response in ["y", "yes"]:
            Cleaner.process_directory(DOWNLOAD_DIRECTORY)
        else:
            print("Operation cancelled.")


if __name__ == "__main__":
    main()
