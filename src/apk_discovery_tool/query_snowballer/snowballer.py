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

"""
Query Snowballer

Expands search queries using any SearchProvider implementation.

This module performs:
    - Controlled BFS expansion of a query graph (seed query are roots and then expand trees from there)
    - Cycle detection
    - Depth limiting
    - Optional per-query expansion limit
"""

from typing import List, Set, Dict
from collections import deque
import time
from tqdm import tqdm


class QuerySnowballer:
    """Performs BFS-based query expansion using a related query provider.

    QuerySnowballer iteratively expands a set of seed queries by fetching related queries from a `provider` (e.g., GoogleQueryFinder). It performs a breadth-first search (BFS) to a maximum depth, respecting global and per-query limits.
    """

    def __init__(
        self,
        provider,
        max_depth: int = 3,
        max_queries: int = 200,
        per_query_limit: int = 10,
    ):
        self.provider = provider
        self.max_depth = max_depth
        self.max_queries = max_queries
        self.per_query_limit = per_query_limit

    def expand(self, seed_queries: List[str]) -> List[str]:
        """Expands a list of seed queries using BFS and the query provider.

        Iteratively fetches related queries for each seed query. Finds new queries up to max_depth while constrained to max_queries and per_query_limit. Stops if no new queries are found in a BFS layer (convergence).

        Args:
            Initial queries to expand.

        Returns:
            A list of unique queries collected, including the seeds.
        """
        visited: Set[str] = set()
        queue = deque([(q, 0) for q in seed_queries])

        last_run_size = 0  # track size from the previous check to detect convergence

        while queue:
            current_level_size = len(queue)
            last_run_size = len(visited)

            for _ in tqdm(range(current_level_size), desc=f"BFS Depth {queue[0][1]}"):
                # Perform BFS
                query, depth = queue.popleft()

                # Ensure we haven't hit max depth
                if depth > self.max_depth or query in visited:
                    continue

                # Visit the query
                visited.add(query)

                # If after we visit we are at max limit then stop
                if len(visited) >= self.max_queries:
                    print("[Snowballer] Reached maximum query limit.")
                    return list(visited)

                # Find related queries with error handling in case rate limited
                try:
                    related = self.provider.get_related_queries(
                        query, self.per_query_limit
                    )
                except Exception as e:
                    print(f"[Snowballer] Error fetching '{query}': {e}")
                    continue

                # For all the related queries ensure they aren't visited or already in the queue before adding
                for r in related:
                    if r not in visited and r not in queue:
                        queue.append((r, depth + 1))

                # Sleep to throttle a bit to avoid getting rate limited by provider
                time.sleep(0.2)

            # Check convergence after finishing the entire BFS level
            if len(visited) == last_run_size:
                print("[Snowballer] Converged — no new unique queries found.")
                break

        return list(visited)
