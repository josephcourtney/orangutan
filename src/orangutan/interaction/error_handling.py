"""Module for handling API exchange errors."""


class APIErrorHandler:
    """Class to handle API errors, retries, and tombstoning."""

    def handle_error(self, error_data: dict) -> dict:
        """
        Handle an API error.

        Args:
            error_data (dict): The error data.

        Returns
        -------
            dict: The result of the error handling.
        """
        raise NotImplementedError

    def retry_request(self, request_data: dict) -> dict:
        """
        Retry a failed API request.

        Args:
            request_data (dict): The request data.

        Returns
        -------
            dict: The retried request response.
        """
        raise NotImplementedError

    def tombstone_request(self, request_data: dict) -> None:
        """
        Tombstone a failed API request.

        Args:
            request_data (dict): The request data.
        """
        raise NotImplementedError
