class QueryProvider:
    def get_related_queries(self, query: str, query_limit: int) -> list[str]:
        """
        Interface to get related search queries and output them as a list of strings.

        Parameters:
        query: The query string from which related queries are fetched
        query_limit: The maximum number of related queries to return

        Returns:
        A list of related search query strings
        """
        raise NotImplementedError("This method should be overridden by subclasses.")

    def filter_queries(self, suggestions: list[str]) -> list[str]:
        """
        Filters the list of queries to ensure it does not contain blacklisted terms.

        Parameters:
        suggestions: A list of suggestions strings to be filtered

        Returns:
        A filtered list of suggested strings
        """
        blacklist = {"ipad", "iphone", "ios", "apple"}

        filtered_queries = [
            s for s in suggestions if not any(b in s.lower() for b in blacklist)
        ]

        return filtered_queries
