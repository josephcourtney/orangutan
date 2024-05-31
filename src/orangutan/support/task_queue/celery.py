"""Celery implementation of a task queue."""

from collections.abc import Callable

from .abc import TaskQueue


class CeleryTaskQueue(TaskQueue):
    """Celery backend for task queue."""

    def __init__(self, broker_url: str, backend_url: str):
        """
        Initialize the Celery task queue.

        Args:
            broker_url (str): The URL of the broker.
            backend_url (str): The URL of the backend.
        """
        raise NotImplementedError

    def add_task(self, task: Callable) -> None:
        """
        Add a task to the Celery queue.

        Args:
            task (Callable): The task to add.
        """
        raise NotImplementedError

    def get_task(self) -> Callable:
        """
        Get a task from the Celery queue.

        Returns
        -------
            Callable: The next task in the queue.
        """
        raise NotImplementedError

    def complete_task(self, task: Callable) -> None:
        """
        Mark a task as complete in the Celery queue.

        Args:
            task (Callable): The task to complete.
        """
        raise NotImplementedError
