"""Module for managing configuration files."""


class ConfigurationManager:
    """Class to manage loading and reloading of configuration files."""

    def load_config(self, config_file: str) -> dict:
        """
        Load configuration from a file.

        Args:
            config_file (str): The configuration file path.

        Returns
        -------
            dict: The configuration data.
        """
        raise NotImplementedError

    def reload_config(self, config_file: str) -> dict:
        """
        Reload configuration from a file.

        Args:
            config_file (str): The configuration file path.

        Returns
        -------
            dict: The reloaded configuration data.
        """
        raise NotImplementedError
