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
        """
        raise NotImplementedError("Must be implemented in subclass.")

    def clean_title(self, title: str):
        # Added this to remove " - Apps on Google Play" suffix from titles returned by Google Play store search results
        clean_title = title.replace(" - Apps on Google Play", "")
        return clean_title.strip()
