from googleapiclient.discovery import build
from apk_finder.base_apk_searcher import BaseAPKSearcher


class GoogleAPKSearcher(BaseAPKSearcher):
    """Concrete implementation of BaseSearcher using Google Custom Search API."""

    def __init__(self, api_key: str = "", search_engine_id: str = ""):
        if api_key == "" or search_engine_id == "":
            raise ValueError("API key and Search Engine ID must be provided.")

        self._service = build("customsearch", "v1", developerKey=api_key)
        self._search_engine_id = search_engine_id

    def search_apks(self, query: str, num_results: int = 10):
        """Search for APKs using Google Custom Search API.

        Args:
            query (str): Search query.
            num_results (int): Maximum number of results.

        Returns:
            List[Dict]: Each dict contains "title" and "snippet".
        """
        response = (
            self._service.cse()
            .list(q=query, cx=self._search_engine_id, num=num_results)
            .execute()
        )

        results = []
        for item in response.get("items", []):
            title = self.clean_title(item.get("title", ""))
            snippet = item.get("snippet", "")
            results.append({"title": title, "snippet": snippet})
        return results
