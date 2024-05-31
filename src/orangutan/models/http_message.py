"""Model for HTTP messages."""

from datetime import datetime

from sqlmodel import SQLModel


class HTTPMessage(SQLModel):
    """SQLModel for HTTP messages."""

    id: int
    request_data: dict
    response_data: dict
    timestamp: datetime
