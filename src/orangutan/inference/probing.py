"""Module for actively probing APIs to infer endpoints and parameters."""


class APIProber:
    """Class to probe APIs and infer endpoints and parameters."""

    def probe_endpoint(self, endpoint: str) -> dict:
        """
        Probe a specific API endpoint.

        Args:
            endpoint (str): The API endpoint to probe.

        Returns
        -------
            dict: Inferred information about the endpoint.
        """
        raise NotImplementedError

    def infer_endpoints_and_parameters(self, base_url: str) -> dict:
        """
        Infer API endpoints and parameters by probing.

        Args:
            base_url (str): The base URL of the API.

        Returns
        -------
            dict: Inferred endpoints and parameters.
        """
        raise NotImplementedError
