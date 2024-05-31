"""Module for collecting API specifications."""


class APISpecificationCollector:
    """Class to find and retrieve API specifications."""

    def find_specifications(self) -> list[str]:
        """
        Find available API specifications.

        Returns
        -------
            List[str]: A list of API specification URLs.
        """
        raise NotImplementedError

    def retrieve_specification(self, url: str) -> dict:
        """
        Retrieve an API specification from a given URL.

        Args:
            url (str): The URL of the API specification.

        Returns
        -------
            dict: The API specification.
        """
        raise NotImplementedError
