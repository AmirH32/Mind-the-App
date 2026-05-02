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

        # Remove apps that are likely to be iOS
        filtered_queries = [
            s for s in suggestions if not any(b in s.lower() for b in blacklist)
        ]

        return filtered_queries
