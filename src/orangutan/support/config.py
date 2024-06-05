"""Module for managing configuration files."""

import atexit
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar

import dotenv
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
)
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from orangutan.support.helpers import RSAPrivateKey, RSAPublicKey, Singleton


class ConfigFileError(Exception):
    """Exception raised for errors in the configuration file."""


class BaseConfigManager(ABC, FileSystemEventHandler):
    """Abstract base class for configuration management."""

    ConfigModelType: ClassVar[type[BaseModel]]
    RESERVED_ATTRIBUTES: set[str]

    def __init__(self, path: Path | str):
        self.path: Path = Path(path).resolve()
        self._paused: bool = False

        if self.path.exists():
            self.load()
        else:
            self._config: BaseModel = self.ConfigModelType()
            self.save()

        self._observer = Observer()
        self._observer.schedule(self, path=self.path.parent, recursive=False)
        self._observer.start()
        atexit.register(self._cleanup)

        self.RESERVED_ATTRIBUTES = set(self.__dict__.keys())

    def _cleanup(self):
        self._observer.stop()
        self._observer.join()

    def on_modified(self, event):
        """Handle the file modification event."""
        if event.src_path == str(self.path) and not self._paused:
            self.load()

    def load(self):
        self._config = self.ConfigModelType(**self.load_file())

    def save(self):
        """Save the current configuration to the file."""
        self.save_file(self._config.model_dump())

    @abstractmethod
    def save_file(self, settings: dict) -> None:
        pass

    @abstractmethod
    def load_file(self) -> dict:
        pass

    def __getattr__(self, item: str) -> Any:  # noqa: ANN401
        """Get setting from the internal _config object."""
        if hasattr(self._config, item):
            return getattr(self._config, item)
        msg = f"'{self.__class__.__name__}' object has no attribute '{item}'"
        raise AttributeError(msg)

    def __setattr__(self, key: str, value: Any) -> None:  # noqa: ANN401
        """Set setting to value in the internal _config object or the instance itself."""
        if key in self.RESERVED_ATTRIBUTES:
            super().__setattr__(key, value)
        else:
            setattr(self._config, key, value)
            self.save()

    def dump(self) -> dict:
        return self._config.model_dump()


class JSONConfigMixin:
    path: Path

    def load_file(self) -> dict:
        """Read the configuration from the JSON file."""
        try:
            with self.path.open("r", encoding="utf-8") as f:
                settings = json.load(f)
        except (OSError, json.JSONDecodeError, ValidationError) as e:
            msg = "Failed to load configuration"
            raise ConfigFileError(msg) from e

        if not isinstance(settings, dict):
            msg = "Failed to load configuration: config file must contain a single JSON object."
            raise ConfigFileError(msg)
        return settings

    def save_file(self, settings: dict) -> None:
        """Save the current configuration to the JSON file."""
        self._paused = True
        try:
            with self.path.open("w", encoding="utf-8") as f:
                json.dump(settings, f, indent=4)
        except OSError as e:
            msg = "Failed to save configuration"
            raise ConfigFileError(msg) from e
        finally:
            self._paused = False


class DotenvConfigMixin:
    path: Path

    def load_file(self) -> dict:
        """Load sensitive settings from the .env file."""
        return dotenv.dotenv_values(self.path)

    def save_file(self, settings: dict) -> None:
        """Save the current keys to the .env file."""
        self._paused = True
        try:
            for key, value in settings.items():
                dotenv.set_key(self.path, key, value)
        except Exception as e:
            msg = "Failed to save configuration"
            raise ConfigFileError(msg) from e
        finally:
            self._paused = False


class ConfigModel(BaseModel):
    hot_reload: bool = Field(default=True)
    key1: bool = Field(default=True)
    key2: str | None = Field(default="default_value")
    key3: int | None = Field(default=42)


class Config(BaseConfigManager, JSONConfigMixin, metaclass=Singleton):
    ConfigModelType = ConfigModel

    def __init__(self, config_path: Path | str = "./config.json"):
        super().__init__(config_path)


class SecretModel(BaseModel):
    # model_config = ConfigDict(arbitrary_types_allowed=True)
    private_key: RSAPrivateKey
    public_key: RSAPublicKey


class Secrets(BaseConfigManager, DotenvConfigMixin, metaclass=Singleton):
    ConfigModelType = SecretModel

    def __init__(self, dotenv_path: Path | str | None = None):
        super().__init__(Path(dotenv_path or dotenv.find_dotenv()))


def generate_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate new RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key
