from googleapiclient.discovery import build
from .base_query_provider import QueryProvider
import requests
from dotenv import load_dotenv
from typing import List
import os

load_dotenv()


class GoogleQueryFinder(QueryProvider):
    """Fetches related search queries using Google's Suggest API.

    This class provides a concrete implementation of `QueryProvider` that
    retrieves related search queries for a given query string using the
    Google Suggest service.

    Attributes:
        _url (str): Base URL for Google Suggest API requests.
    """

    def __init__(self):
        self._url = "https://suggestqueries.google.com/complete/search"

    def get_related_queries(self, query: str, query_limit: int = 10) -> List[str]:
        """
        Fetches related search queries using the google suggest query API

        Parameters:
        query (str): The search query to get related queries for.
        query_limit (int): The maximum number of related queries to return (default: 10).

        Returns:
        List[str]: A list of related search queries.
        """

        params = {"client": "firefox", "q": query}
        resp = requests.get(self._url, params=params)
        suggestions = resp.json()[1]  # second element has suggestions
        suggestions = suggestions[:10]  # truncates to the query_limit

        suggestions = self.filter_queries(suggestions)

        return suggestions
