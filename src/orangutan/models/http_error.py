"""Model for HTTP exchange errors."""

from datetime import datetime

from sqlmodel import SQLModel


class HTTPError(SQLModel):
    """SQLModel for HTTP exchange errors."""

    id: int
    status_code: int
    error_message: str
    timestamp: datetime
