"""
Query Snowballer
----------------
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

    QuerySnowballer iteratively expands a set of seed queries by fetching
    related queries from a `provider` (e.g., GoogleQueryFinder). It performs
    a breadth-first search (BFS) to a maximum depth, respecting global and
    per-query limits.

    Attributes:
        provider: An instance of SearchProvider (e.g. GoogleSearchProvider) provider implementing
                `get_related_queries(query, query_limit)`.
        max_depth (int): Maximum BFS depth to explore.
        max_queries (int): Global limit on total queries collected.
        per_query_limit (int): Limit of related queries fetched per query.
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

        Iteratively fetches related queries for each seed query and newly discovered
        queries, up to `max_depth` BFS levels, while respecting `max_queries` and
        `per_query_limit`. Stops if no new queries are found in a BFS layer
        (convergence).

        Args:
            seed_queries (List[str]): Initial queries to expand.

        Returns:
            List[str]: A list of unique queries collected, including the seeds.

        Notes:
            - The function sleeps briefly (0.2s) between requests to throttle API calls.
            - Any errors from the provider are caught and logged; processing continues.
            - Uses tqdm progress bars to indicate BFS depth processing.
        """
        visited: Set[str] = set()
        queue = deque([(q, 0) for q in seed_queries])

        last_run_size = 0  # track size from the previous check to detect convergence

        while queue:
            current_level_size = len(queue)
            last_run_size = len(visited)

            for _ in tqdm(range(current_level_size), desc=f"BFS Depth {queue[0][1]}"):
                query, depth = queue.popleft()
                if depth > self.max_depth or query in visited:
                    continue
                visited.add(query)
                if len(visited) >= self.max_queries:
                    print("[Snowballer] Reached maximum query limit.")
                    return list(visited)
                try:
                    related = self.provider.get_related_queries(
                        query, self.per_query_limit
                    )
                except Exception as e:
                    print(f"[Snowballer] Error fetching '{query}': {e}")
                    continue

                for r in related:
                    if r not in visited and r not in queue:
                        queue.append((r, depth + 1))

                # Sleep to throttle a bit
                time.sleep(0.2)

            # Check convergence after finishing the entire BFS level
            if len(visited) == last_run_size:
                print("[Snowballer] Converged — no new unique queries found.")
                break

        return list(visited)
