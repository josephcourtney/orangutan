"""In-memory implementation of a task queue."""

from collections.abc import Callable

from .abc import TaskQueue


class MemoryTaskQueue(TaskQueue):
    """In-memory priority heap backend for task queue."""

    def __init__(self):
        """Initialize the memory task queue."""
        raise NotImplementedError

    def add_task(self, task: Callable) -> None:
        """
        Add a task to the memory queue.

        Args:
            task (Callable): The task to add.
        """
        raise NotImplementedError

    def get_task(self) -> Callable:
        """
        Get a task from the memory queue.

        Returns
        -------
            Callable: The next task in the queue.
        """
        raise NotImplementedError

    def complete_task(self, task: Callable) -> None:
        """
        Mark a task as complete in the memory queue.

        Args:
            task (Callable): The task to complete.
        """
        raise NotImplementedError
