"""Model for JSON schemas used for data validation and parsing."""

from sqlmodel import SQLModel


class JSONSchema(SQLModel):
    """SQLModel for JSON schemas."""

    id: int
    schema_data: dict
    version: str
    predecessor_id: int | None
