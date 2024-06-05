import os
from abc import ABCMeta
from collections.abc import Callable
from typing import (
    Annotated,
    Any,
    ClassVar,
    cast,
)

from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import (
    GetJsonSchemaHandler,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema


class Singleton(ABCMeta):
    _instances: ClassVar[dict] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


class RSAPrivateKeyAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(  # noqa: PLW3201, D105
        cls,
        _source_type: Any,  # noqa: ANN401
        _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_pem(private_key_pem: str) -> rsa.RSAPrivateKey:
            return cast(
                rsa.RSAPrivateKey, serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            )

        def serialize_to_pem(private_key: rsa.RSAPrivateKey) -> str:
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

        from_str_schema = core_schema.chain_schema([
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(validate_from_pem),
        ])

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(rsa.RSAPrivateKey),
                from_str_schema,
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_pem),
        )

    @classmethod
    def __get_pydantic_json_schema__(  # noqa: PLW3201, D105
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())


RSAPrivateKey = Annotated[rsa.RSAPrivateKey, RSAPrivateKeyAnnotation]


class RSAPublicKeyAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(  # noqa: PLW3201, D105
        cls,
        _source_type: Any,  # noqa: ANN401
        _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_pem(public_key_pem: str) -> rsa.RSAPublicKey:
            return cast(rsa.RSAPublicKey, serialization.load_pem_public_key(public_key_pem.encode()))

        def serialize_to_pem(public_key: rsa.RSAPublicKey) -> str:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

        from_str_schema = core_schema.chain_schema([
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(validate_from_pem),
        ])

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(rsa.RSAPublicKey),
                from_str_schema,
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_pem),
        )

    @classmethod
    def __get_pydantic_json_schema__(  # noqa: PLW3201, D105
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())


RSAPublicKey = Annotated[rsa.RSAPublicKey, RSAPublicKeyAnnotation]


class ECPrivateKeyAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(  # noqa: PLW3201, D105
        cls,
        _source_type: Any,  # noqa: ANN401
        _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_pem(private_key_pem: str) -> ec.EllipticCurvePrivateKey:
            return cast(
                ec.EllipticCurvePrivateKey,
                serialization.load_pem_private_key(private_key_pem.encode(), password=None),
            )

        def serialize_to_pem(private_key: ec.EllipticCurvePrivateKey) -> str:
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

        from_str_schema = core_schema.chain_schema([
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(validate_from_pem),
        ])

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ec.EllipticCurvePrivateKey),
                from_str_schema,
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_pem),
        )

    @classmethod
    def __get_pydantic_json_schema__(  # noqa: PLW3201, D105
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())


ECPrivateKey = Annotated[ec.EllipticCurvePrivateKey, ECPrivateKeyAnnotation]


class ECPublicKeyAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(  # noqa: PLW3201, D105
        cls,
        _source_type: Any,  # noqa: ANN401
        _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_pem(public_key_pem: str) -> ec.EllipticCurvePublicKey:
            return cast(ec.EllipticCurvePublicKey, serialization.load_pem_public_key(public_key_pem.encode()))

        def serialize_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

        from_str_schema = core_schema.chain_schema([
            core_schema.str_schema(),
            core_schema.no_info_plain_validator_function(validate_from_pem),
        ])

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(ec.EllipticCurvePublicKey),
                from_str_schema,
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_pem),
        )

    @classmethod
    def __get_pydantic_json_schema__(  # noqa: PLW3201, D105
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())


ECPublicKey = Annotated[ec.EllipticCurvePublicKey, ECPublicKeyAnnotation]


class AESKeyAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(  # noqa: PLW3201, D105
        cls,
        _source_type: Any,  # noqa: ANN401
        _handler: Callable[[Any], core_schema.CoreSchema],
    ) -> core_schema.CoreSchema:
        def validate_from_bytes(key_bytes: bytes) -> bytes:
            if len(key_bytes) not in {16, 24, 32}:
                msg = "Invalid AES key length"
                raise ValueError(msg)
            return key_bytes

        def serialize_to_bytes(key: bytes) -> bytes:
            return key

        from_bytes_schema = core_schema.chain_schema([
            core_schema.bytes_schema(),
            core_schema.no_info_plain_validator_function(validate_from_bytes),
        ])

        return core_schema.json_or_python_schema(
            json_schema=from_bytes_schema,
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(bytes),
                from_bytes_schema,
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_bytes),
        )

    @classmethod
    def __get_pydantic_json_schema__(  # noqa: PLW3201, D105
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.bytes_schema())


AESKey = Annotated[bytes, AESKeyAnnotation]


# Utility functions


def generate_rsa_key_pair(key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ec_key_pair(
    curve: ec.EllipticCurve | None,
) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(curve or ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def generate_aes_key(length: int = 32) -> bytes:
    if length not in {16, 24, 32}:
        msg = "Invalid AES key length"
        raise ValueError(msg)
    return os.urandom(length)


def hash_password(password: str, salt: bytes | None = None, iterations: int = 100_000) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())
    return hashed_password, salt


def verify_password(password: str, hashed_password: bytes, salt: bytes, iterations: int = 100_000) -> bool:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), hashed_password)
    except InvalidKey:
        return False
    else:
        return True


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    else:
        return True
