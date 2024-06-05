# ruff: noqa: INP001
import dill  # noqa: S403 # security risk is dealt with, somewhat, by code signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding,
)
from sqlalchemy import Column
from sqlalchemy.engine import Dialect
from sqlalchemy.types import BLOB, TypeDecorator
from sqlmodel import Field, SQLModel

from orangutan.support.config import Config


class ClassType(TypeDecorator):
    impl = BLOB

    @staticmethod
    def process_bind_param(value: type | None, dialect: Dialect) -> bytes | None:  # noqa: ARG004
        config = Config()
        if value is None:
            return None
        pickled_data = dill.dumps(value)
        signature = config.private_key.sign(
            pickled_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return dill.dumps({"data": pickled_data, "signature": signature})

    @staticmethod
    def process_result_value(value: bytes | None, dialect: Dialect) -> type | None:  # noqa: ARG004
        config = Config()
        if value is None:
            return None
        pickled_object = dill.loads(value)  # noqa: S301
        pickled_data = pickled_object["data"]
        signature = pickled_object["signature"]

        config.public_key.verify(
            signature,
            pickled_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return None if (unpickled := dill.loads(pickled_data)) is None else unpickled  # noqa: S301

    @classmethod
    def __get_pydantic_json_schema__(cls, handler):  # noqa: PLW3201
        """Return the Pydantic JSON schema for the PickleType."""
        return {"type": "string", "title": "PickleType"}

    @classmethod
    def __modify_schema__(cls, field_schema):  # noqa: PLW3201
        """Modify the schema of a field by updating its type to 'string'."""
        field_schema.update(type="string")


class ClassModel(SQLModel, table=True):
    name: str = Field(primary_key=True)
    type: ClassType | None = Field(sa_column=Column(ClassType, default=None))

    class Config:  # noqa: D106
        arbitrary_types_allowed = True
