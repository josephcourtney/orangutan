"""Module for validating API responses."""


class APIResponseValidator:
    """Class to validate API responses and instantiate Pydantic models."""

    def validate_response(self, response: dict) -> bool:
        """
        Validate an API response.

        Args:
            response (dict): The API response.

        Returns
        -------
            bool: True if valid, False otherwise.
        """
        raise NotImplementedError

    def instantiate_model(self, response: dict) -> type:
        """
        Instantiate a Pydantic model from an API response.

        Args:
            response (dict): The API response.

        Returns
        -------
            type: The instantiated Pydantic model.
        """
        raise NotImplementedError
