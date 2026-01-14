from abc import ABC, abstractmethod
from typing import List, Dict


class BaseAPKSearcher(ABC):
    """
    Abstract base class for search engine objects.
    All searcher implementations must inherit from this class.
    """

    @abstractmethod
    def search_apks(self, query: str, num_results: int = 10) -> List[Dict]:
        """
        Search for APKs given a query.

        Parameters:
            query (str): The search query (e.g., "Parental Control App").
            num_results (int): Maximum number of search results to retrieve.

        Returns:
            List[Dict]: Each dict should contain at least:
                - "query": original query
                - "title": result title
                - "link": APK URL
                - "desc": description
        """
        raise NotImplementedError("Must be implemented in subclass.")

    def clean_title(self, title: str):
        clean_title = title.replace(" - Apps on Google Play", "")
        return clean_title.strip()
