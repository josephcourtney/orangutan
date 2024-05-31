"""Module specifying the base interface for a task queue."""

from abc import ABC, abstractmethod
from collections.abc import Callable


class TaskQueue(ABC):
    """Abstract base class for task queues."""

    @abstractmethod
    def add_task(self, task: Callable) -> None:
        """
        Add a task to the queue.

        Args:
            task (Callable): The task to add.
        """
        raise NotImplementedError

    @abstractmethod
    def get_task(self) -> Callable:
        """
        Get a task from the queue.

        Returns
        -------
            Callable: The next task in the queue.
        """
        raise NotImplementedError

    @abstractmethod
    def complete_task(self, task: Callable) -> None:
        """
        Mark a task as complete.

        Args:
            task (Callable): The task to complete.
        """
        raise NotImplementedError
