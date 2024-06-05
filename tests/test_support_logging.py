# ruff: noqa: PLR2004
import json
import logging
import time
from logging.config import dictConfig
from pathlib import Path

import pytest
from orangutan.support.logging import (
    JSONFormatter,
    NonErrorFilter,
    get_logger,
    logging_config,
    serialize,
)


@pytest.fixture()
def sample_data():
    class CustomObject:
        def __init__(self, value):
            self.value = value

        def serialize(self):
            return {"value": self.value}

    class SlotsObject:
        __slots__ = ["value"]

        def __init__(self, value):
            self.value = value

    return {
        "simple_data": [123, 45.67, "test", b"bytes", True, None],
        "collection_data": [[1, 2, 3], (4, 5, 6), {7, 8, 9}, frozenset([10, 11, 12])],
        "dict_data": {"key1": "value1", "key2": 2, "key3": [1, 2, 3]},
        "custom_object": CustomObject(42),
        "slots_object": SlotsObject(99),
        "nested_structure": {"list": [1, {"inner_dict": "value"}, (2, 3)], "set": {4, 5, 6}},
    }


class Example:
    def __init__(self, x, y):
        self.x = x
        self.y = y


def test_serialize_simple_types():
    assert serialize(1) == 1
    assert serialize("string") == "string"
    assert serialize([1, 2, 3]) == [1, 2, 3]
    assert serialize({"a": 1, "b": 2}) == {"a": 1, "b": 2}


def test_serialize_complex_object():
    obj = Example(1, [2, 3])
    serialized_obj = serialize(obj)
    print(serialized_obj)
    assert serialized_obj == {"x": 1, "y": [2, 3], "class": "Example"}


def test_json_formatter():
    formatter = JSONFormatter(fmt_keys={"level": "levelname", "message": "message", "timestamp": "created"})
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    formatted_log = formatter.format(record)
    log_dict = json.loads(formatted_log)
    assert log_dict["message"] == "Test message"
    assert log_dict["level"] == "INFO"
    assert "timestamp" in log_dict


@pytest.fixture()
def setup_logging():
    dictConfig(logging_config)
    yield get_logger()
    # Cleanup: remove log files
    log_file = logging_config["handlers"]["file_json"]["filename"]
    if Path(log_file).exists():
        Path(log_file).unlink()


def test_logging_setup(setup_logging):
    logger = setup_logging
    logger.debug("This is a debug message")
    logger.warning("This is a warning message")

    # Force flush handlers to ensure logs are written to the file
    for handler in logger.handlers:  # sourcery skip: no-loop-in-tests
        handler.flush()

    log_file = logging_config["handlers"]["file_json"]["filename"]
    assert Path(log_file).exists()

    time.sleep(0.1)

    with Path(log_file).open(encoding="utf-8") as f:
        logs = f.readlines()

    assert len(logs) > 0
    log_entry = json.loads(logs[0])
    assert log_entry["message"] in {"This is a debug message", "This is a warning message"}
    assert log_entry["level"] in {"DEBUG", "WARNING"}


def test_non_error_filter():
    logger = get_logger()
    non_error_filter = NonErrorFilter()
    logger.addFilter(non_error_filter)

    assert (
        non_error_filter.filter(
            logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname=__file__,
                lineno=10,
                msg="Info",
                args=(),
                exc_info=None,
            )
        )
        is True
    )
    assert (
        non_error_filter.filter(
            logging.LogRecord(
                name="test",
                level=logging.WARNING,
                pathname=__file__,
                lineno=10,
                msg="Warning",
                args=(),
                exc_info=None,
            )
        )
        is False
    )


@pytest.mark.parametrize("i", range(6), ids=lambda i: f"item_{i}")
def test_simple_data(sample_data, i):
    item = sample_data["simple_data"][i]
    assert serialize(item) == item


@pytest.mark.parametrize("i", range(4), ids=lambda i: f"item_{i}")
def test_collection_data(sample_data, i):
    collection = sample_data["collection_data"][i]
    serialized = serialize(collection)
    assert isinstance(serialized, list)
    assert len(serialized) == len(collection)
    assert serialized == list(collection)


def test_dict_data(sample_data):
    serialized = serialize(sample_data["dict_data"])
    assert isinstance(serialized, dict)
    assert serialized == sample_data["dict_data"]
    assert isinstance(serialized, dict)


def test_slots_object(sample_data):
    serialized = serialize(sample_data["slots_object"])
    assert isinstance(serialized, dict)
    assert serialized["value"] == 99
    assert serialized["class"] == "SlotsObject"


def test_nested_structure(sample_data):
    serialized = serialize(sample_data["nested_structure"])
    assert isinstance(serialized, dict)
    assert "list" in serialized
    assert isinstance(serialized["list"], list)
    assert isinstance(serialized["list"][1], dict)
    assert serialized["list"][1]["inner_dict"] == "value"
    assert serialized["set"] == [4, 5, 6]


def test_unsupported_type():
    class Unsupported:
        pass

    assert serialize(Unsupported()) == {"class": "Unsupported"}


def test_self_reference():
    obj = []
    obj.append(obj)
    serialized = serialize(obj)
    assert serialized == [("CircularReference", ())]


def test_circular_reference():
    obj1 = {}
    obj2 = {"ref": obj1}
    obj1["ref"] = obj2
    serialized = serialize(obj1)
    assert serialized["ref"]["ref"] == ("CircularReference", ())


class CustomIterable:
    def __init__(self, items):
        self.items = items

    def __iter__(self):
        return iter(self.items)


class VariableLengthIterable:
    def __init__(self, items):
        self.items = items

    def __iter__(self):
        return iter(self.items)


@pytest.mark.parametrize(
    ("gen", "expected"),
    [
        (iter(range(3)), {"__iter__": [0, 1, 2], "class": "range_iterator"}),
        (iter(range(0)), {"__iter__": [], "class": "range_iterator"}),
        (iter(range(1000)), {"__iter__": list(range(8)), "class": "range_iterator"}),
        ((x for x in iter([1, "two", 3.0])), {"__iter__": [1, "two", 3.0], "class": "generator"}),
    ],
)
def test_generator(gen, expected):  # sourcery skip: simplify-generator
    serialized = serialize(gen)
    assert serialized == expected


@pytest.mark.parametrize(
    ("iterable", "expected"),
    [
        (lambda: CustomIterable([1, 2, 3]), {"__iter__": [1, 2, 3], "class": "CustomIterable"}),
        (lambda: CustomIterable([]), {"__iter__": [], "class": "CustomIterable"}),
        (
            lambda: VariableLengthIterable([1, 2, 3, 4, 5]),
            {"__iter__": [1, 2, 3, 4, 5], "class": "VariableLengthIterable"},
        ),
        (
            lambda: VariableLengthIterable([VariableLengthIterable([1, 2]), 3, 4]),
            {
                "__iter__": [{"__iter__": [1, 2], "class": "VariableLengthIterable"}, 3, 4],
                "class": "VariableLengthIterable",
            },
        ),
        (
            lambda: VariableLengthIterable([1, "two", 3.0]),
            {"__iter__": [1, "two", 3.0], "class": "VariableLengthIterable"},
        ),
    ],
)
def test_iterable(iterable, expected):
    serialized = serialize(iterable())
    assert serialized == expected
