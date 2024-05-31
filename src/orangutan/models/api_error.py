"""Model for API response validation errors."""

from datetime import datetime

from sqlmodel import SQLModel


class APIError(SQLModel):
    """SQLModel for API response validation errors."""

    id: int
    error_code: int
    error_message: str
    timestamp: datetime
