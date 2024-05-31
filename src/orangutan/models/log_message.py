"""Model for log messages."""

from datetime import datetime

from sqlmodel import SQLModel


class LogMessage(SQLModel):
    """SQLModel for log messages."""

    id: int
    log_level: str
    message: str
    timestamp: datetime
