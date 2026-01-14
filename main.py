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
from utils.config import GOOGLE_API_KEY, GOOGLE_SEARCH_ENGINE_ID

load_dotenv()

EXPANDED_QUERIES_FILE = "/home/malan/Documents/files/expanded_queries.json"
SEARCH_RESULTS_FILE = "/home/malan/Documents/files/search_results.json"


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
        time.sleep(0.2)
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


def main():
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
        help="Load APK search results from file",
    )
    parser.add_argument(
        "-a",
        "--scrape-apkmirror",
        action="store_true",
        help="Scrape APKMirror for APK download links",
    )
    args = parser.parse_args()

    # If no flags are provided, default to loading queries and results
    if not any(vars(args).values()):
        args.load_queries = True
        args.load_results = True
        args.scrape_apkmirror = True
        print(
            "No flags provided. Defaulting to loading queries and search results from files.\n"
        )

    # Step 1: Queries
    if args.generate_queries:
        queries = find_and_save_queries()
    elif args.load_queries:
        queries = load_json(EXPANDED_QUERIES_FILE)
        print(f"Loaded {len(queries)} queries from {EXPANDED_QUERIES_FILE}")
    else:
        queries = []

    # Step 2: APK Search
    if args.search_apks and queries:
        filtered = search_and_save_apks(queries)
    elif args.load_results:
        filtered = load_json(SEARCH_RESULTS_FILE)
        print(f"Loaded {len(filtered)} APK search results from {SEARCH_RESULTS_FILE}")
    else:
        filtered = []

    # Step 3: Print search results
    if filtered:
        for i in filtered:
            print(f"{50 * '='} \nTitle: {i['title']} \nSnippet: {i['snippet']}")

    # Step 4: APKMirror scraping
    if args.scrape_apkmirror and filtered:
        scraper = APKMirrorScraper(max_results=5)
        all_apk_downloads = []
        for result in tqdm(filtered[:1], desc="Obtaining APK info from APKMirror"):
            print(filtered[0])
            all_apk_downloads.append(scraper.search_and_download(result["title"]))

        print("\nAPKMirror scraping done.")
        # Optional: save or process all_apk_downloads
        #
    for apk_results in all_apk_downloads:
        for apk in apk_results:
            print(apk.to_dict())


if __name__ == "__main__":
    main()
