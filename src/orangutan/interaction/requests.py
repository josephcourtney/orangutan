"""Module for asynchronous API requests."""


class AsyncAPIRequester:
    """Class to send asynchronous API requests and handle responses."""

    async def send_request(self, request_data: dict) -> dict:
        """
        Send an asynchronous API request.

        Args:
            request_data (dict): The request data.

        Returns
        -------
            dict: The API response.
        """
        raise NotImplementedError

    async def handle_response(self, response: dict) -> dict:
        """
        Handle an asynchronous API response.

        Args:
            response (dict): The API response.

        Returns
        -------
            dict: The processed response.
        """
        raise NotImplementedError
