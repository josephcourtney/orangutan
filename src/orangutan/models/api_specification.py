"""Model for API specifications."""

from sqlmodel import SQLModel


class APISpecification(SQLModel):
    """SQLModel for API specifications."""

    id: int
    specification_data: dict
    version: str
    predecessor_id: int | None
