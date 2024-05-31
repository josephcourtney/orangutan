"""Module for managing rate limiting of API requests."""


class RateLimiter:
    """Class to manage global and per-API rate limits."""

    def limit_global_rate(self, rate: int) -> None:
        """
        Limit the global request rate.

        Args:
            rate (int): The global request rate limit.
        """
        raise NotImplementedError

    def limit_per_api_rate(self, api: str, rate: int) -> None:
        """
        Limit the request rate for a specific API.

        Args:
            api (str): The API identifier.
            rate (int): The request rate limit.
        """
        raise NotImplementedError

    def adapt_rate_limits(self, api: str, conditions: dict) -> None:
        """
        Adapt rate limits based on API and network conditions.

        Args:
            api (str): The API identifier.
            conditions (dict): The network conditions.
        """
        raise NotImplementedError
