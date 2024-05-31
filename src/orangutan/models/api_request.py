"""Model for API requests and responses."""

from datetime import datetime

from sqlmodel import SQLModel


class APIRequest(SQLModel):
    """SQLModel for API requests and responses."""

    id: int
    request_data: dict
    response_data: dict
    timestamp: datetime
