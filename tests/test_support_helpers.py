import random

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from orangutan.support.helpers import (
    AESKey,
    ECPrivateKey,
    ECPublicKey,
    RSAPrivateKey,
    RSAPublicKey,
    generate_aes_key,
    generate_ec_key_pair,
    generate_rsa_key_pair,
    hash_password,
    sign_message,
    verify_password,
    verify_signature,
)
from pydantic import BaseModel, ValidationError


class RSAKeyModel(BaseModel):
    private_key: RSAPrivateKey
    public_key: RSAPublicKey


class ECKeyModel(BaseModel):
    private_key: ECPrivateKey
    public_key: ECPublicKey


class AESKeyModel(BaseModel):
    key: AESKey


@pytest.fixture()
def rsa_key_pair():
    return generate_rsa_key_pair()


@pytest.fixture()
def ec_key_pair():
    return generate_ec_key_pair(ec.SECP256R1())


@pytest.fixture()
def aes_key():
    return generate_aes_key()


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def serialize_public_key(public_key: rsa.RSAPublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def serialize_ec_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def serialize_ec_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


@pytest.mark.parametrize(
    ("key_model", "serialize_private", "serialize_public"),
    [
        (RSAKeyModel, serialize_private_key, serialize_public_key),
        (ECKeyModel, serialize_ec_private_key, serialize_ec_public_key),
    ],
)
def test_key_serialization_deserialization(
    key_model, serialize_private, serialize_public, rsa_key_pair, ec_key_pair
):
    key_pair = rsa_key_pair if key_model is RSAKeyModel else ec_key_pair

    private_key, public_key = key_pair

    private_key_pem = serialize_private(private_key)
    public_key_pem = serialize_public(public_key)

    model = key_model(private_key=private_key_pem, public_key=public_key_pem)
    assert isinstance(model.private_key, type(private_key))
    assert isinstance(model.public_key, type(public_key))
    assert model.private_key.private_numbers() == private_key.private_numbers()
    assert model.public_key.public_numbers() == public_key.public_numbers()

    model = key_model(private_key=private_key, public_key=public_key_pem)
    assert isinstance(model.private_key, type(private_key))
    assert isinstance(model.public_key, type(public_key))
    assert model.private_key.private_numbers() == private_key.private_numbers()
    assert model.public_key.public_numbers() == public_key.public_numbers()

    model = key_model(private_key=private_key_pem, public_key=public_key)
    assert isinstance(model.private_key, type(private_key))
    assert isinstance(model.public_key, type(public_key))
    assert model.private_key.private_numbers() == private_key.private_numbers()
    assert model.public_key.public_numbers() == public_key.public_numbers()

    model = key_model(private_key=private_key, public_key=public_key)
    assert isinstance(model.private_key, type(private_key))
    assert isinstance(model.public_key, type(public_key))
    assert model.private_key.private_numbers() == private_key.private_numbers()
    assert model.public_key.public_numbers() == public_key.public_numbers()


def test_aes_key_serialization_deserialization(aes_key):
    model = AESKeyModel(key=aes_key)
    assert isinstance(model.key, bytes)
    assert model.key == aes_key


@pytest.mark.parametrize(
    ("key_model", "serialize_private", "serialize_public"),
    [
        (RSAKeyModel, serialize_private_key, serialize_public_key),
        (ECKeyModel, serialize_ec_private_key, serialize_ec_public_key),
    ],
)
def test_model_dump_accuracy(key_model, serialize_private, serialize_public, rsa_key_pair, ec_key_pair):
    key_pair = rsa_key_pair if key_model is RSAKeyModel else ec_key_pair

    private_key, public_key = key_pair
    private_pem = serialize_private(private_key)
    public_pem = serialize_public(public_key)

    model = key_model(private_key=private_pem, public_key=public_pem)
    dumped = model.model_dump()

    assert "private_key" in dumped
    assert "public_key" in dumped
    assert dumped["private_key"] == private_pem
    assert dumped["public_key"] == public_pem

    loaded_private_key = serialization.load_pem_private_key(dumped["private_key"].encode(), password=None)
    loaded_public_key = serialization.load_pem_public_key(dumped["public_key"].encode())

    assert isinstance(loaded_private_key, type(private_key))
    assert isinstance(loaded_public_key, type(public_key))
    assert loaded_private_key.private_numbers() == private_key.private_numbers()
    assert loaded_public_key.public_numbers() == public_key.public_numbers()


def test_invalid_rsa_key_deserialization():
    invalid_key_pem = "invalid key"

    with pytest.raises(ValidationError):
        RSAKeyModel(private_key=invalid_key_pem, public_key=invalid_key_pem)


def test_invalid_ec_key_deserialization():
    invalid_key_pem = "invalid key"

    with pytest.raises(ValidationError):
        ECKeyModel(private_key=invalid_key_pem, public_key=invalid_key_pem)


def test_password_hashing_and_verification():
    password = "strong_password"  # noqa: S105
    hashed_password, salt = hash_password(password)

    assert verify_password(password, hashed_password, salt)
    assert not verify_password("wrong_password", hashed_password, salt)


def test_message_signing_and_verification(rsa_key_pair):
    private_key, public_key = rsa_key_pair
    message = b"Test message"

    signature = sign_message(private_key, message)
    assert verify_signature(public_key, message, signature)

    wrong_message = b"Wrong message"
    assert not verify_signature(public_key, wrong_message, signature)


# Additional tests


def test_aes_encryption_decryption(aes_key):
    data = b"Secret message"
    random.seed(1234)
    iv = bytes(random.randint(0, 255) for _ in range(16))  # noqa: S311

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    assert decrypted_data == data


@pytest.mark.parametrize(
    "password",
    [
        "p@ssw0rd!",
        "",
        pytest.param("verylongpassword" * 10, id="long password"),
        pytest.param("short", id="short password"),
        pytest.param("pässwörd", id="non-ASCII password"),
    ],
)
def test_password_hashing_edge_cases(password):
    hashed_password, salt = hash_password(password)

    assert verify_password(password, hashed_password, salt)
    assert not verify_password("different_password", hashed_password, salt)


@pytest.mark.parametrize(
    "message", [b"short", b"long" * 1000, pytest.param(b"medium length message", id="medium message")]
)
def test_signature_with_different_message_lengths(rsa_key_pair, message):
    private_key, public_key = rsa_key_pair

    signature = sign_message(private_key, message)

    assert verify_signature(public_key, message, signature)
    assert not verify_signature(public_key, message + b"1", signature)


@pytest.mark.parametrize("key_length", [16, 24, 32])
def test_aes_key_generation_and_encryption_decryption(key_length):
    aes_key = generate_aes_key(key_length)
    data = b"Secret message"
    random.seed(1234)
    iv = bytes(random.randint(0, 255) for _ in range(16))  # noqa: S311
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    assert decrypted_data == data


def test_invalid_aes_key_length():
    with pytest.raises(ValueError, match="Invalid AES key length"):
        generate_aes_key(20)
