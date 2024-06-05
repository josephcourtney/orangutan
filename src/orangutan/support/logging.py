"""Module for setting up and managing logging."""

import atexit
import datetime as dt
import json
import logging
import logging.config
from collections.abc import Generator, Iterable
from pathlib import Path

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {
            "format": "[%(levelname)s|%(module)s|L%(lineno)d] %(asctime)s: %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S%z",
        },
        "json": {
            "()": f"{__package__}.logging.JSONFormatter",
            "fmt_keys": {
                "level": "levelname",
                "message": "message",
                "timestamp": "timestamp",
                "logger": "name",
                "module": "module",
                "function": "funcName",
                "line": "lineno",
                "thread_name": "threadName",
            },
        },
    },
    "handlers": {
        "stderr": {
            "class": "logging.StreamHandler",
            "level": "WARNING",
            "formatter": "simple",
            "stream": "ext://sys.stderr",
        },
        "file_json": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "json",
            "filename": f"logs/{__package__}.log.jsonl",
            "maxBytes": 1000000,
            "backupCount": 5,
        },
        "queue_handler": {
            "class": "logging.handlers.QueueHandler",
            "handlers": ["stderr", "file_json"],
            "respect_handler_level": True,
        },
    },
    "loggers": {"root": {"level": "DEBUG", "handlers": ["queue_handler"]}},
    "serialization": {
        "max_generator_elements": 16,
    },
}

LOG_RECORD_BUILTIN_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
}


class SerializationError(Exception):
    """Custom exception for serialization errors."""


NO_PARENT = object()
NONE_LITERAL = object()


def serialize(obj):
    stack = [(obj, NO_PARENT, None, ())]
    result = None
    seen = {}

    while stack:
        current_obj, parent, parent_key, path = stack.pop()

        obj_id = id(current_obj)
        if obj_id in seen:
            if parent is not NO_PARENT:
                ref_type = "CircularReference"
                parent[parent_key] = (ref_type, seen[obj_id])
            continue
        if not isinstance(current_obj, int | float | bool | str | None):
            seen[obj_id] = path

        try:
            current_result = serialize_object(current_obj, stack, path)
        except SerializationError as e:
            current_result = str(e)

        if parent is NO_PARENT:
            result = current_result
        else:
            parent[parent_key] = current_result

    if result is None:
        msg = "Failed to serialize the object."
        result = {"error": msg}
    if result is NONE_LITERAL:
        result = None

    return result


def serialize_object(obj, stack, path):  # noqa: C901
    result = None
    match obj:
        case None:
            result = NONE_LITERAL
        case bytes() | str() | int() | float() | bool():
            result = obj
        case list() | tuple() | set() | frozenset():
            result = serialize_collection(obj, stack, path)
        case dict():
            result = serialize_dict(obj, stack, path)
        case _ if hasattr(obj, "serialize") and callable(obj.serialize):
            result = serialize_custom(obj, stack, path)
        case _ if hasattr(obj, "__slots__"):
            result = serialize_slots(obj)
        case type():
            result = serialize_type(obj)
        case _ if isinstance(obj, Generator):
            result = serialize_iterable(obj, stack, path)
        case _ if isinstance(obj, Iterable):
            result = serialize_iterable(obj, stack, path)
        case _ if hasattr(obj, "__dict__"):
            result = serialize_dict_attrs(obj)
        case _:
            msg = f"Unsupported type: {type(obj).__name__}"
            raise SerializationError(msg)
    return result


def serialize_collection(coll, stack, path):
    result = [None] * len(coll)
    stack.extend((item, result, idx, (*path, idx)) for idx, item in enumerate(coll))
    return result


def serialize_dict(dct, stack, path):
    result = {}
    stack.extend((v, result, k, (*path, k)) for k, v in dct.items() if not callable(v))
    return result


def serialize_custom(obj, stack, path):
    serialized = obj.serialize()
    if isinstance(serialized, dict):
        serialized["class"] = obj.__class__.__name__
    stack.append((serialized, NO_PARENT, None, path))
    return serialized


def serialize_slots(obj):
    return {
        slot: getattr(obj, slot)
        for slot in obj.__slots__
        if (hasattr(obj, slot) and not callable(getattr(obj, slot)))
    } | {"class": obj.__class__.__name__}


def serialize_type(cls):
    return {"class": type(cls).__name__, "name": cls.__name__}


def serialize_iterable(itr, stack, path, max_len=8):
    sample = [e for _, e in zip(range(max_len), itr, strict=False)]
    result = {
        "class": itr.__class__.__name__,
        "__iter__": sample,
    }
    stack.extend((item, result["__iter__"], idx, (*path, idx)) for idx, item in enumerate(sample))
    return result


def serialize_dict_attrs(obj):
    return {k: v for k, v in obj.__dict__.items() if not k.startswith("_") and not callable(v)} | {
        "class": obj.__class__.__name__
    }


class JSONFormatter(logging.Formatter):
    def __init__(self, *, fmt_keys=None):
        super().__init__()
        self.fmt_keys = fmt_keys if fmt_keys is not None else {}

    def format(self, record):
        message = self._prepare_log_dict(record)
        return json.dumps(message, default=str)

    def _prepare_log_dict(self, record):
        always_fields = {
            "message": record.getMessage(),
            "timestamp": dt.datetime.fromtimestamp(record.created, tz=dt.UTC).isoformat(),
        }
        if record.exc_info is not None:
            always_fields["exc_info"] = self.formatException(record.exc_info)

        if record.stack_info is not None:
            always_fields["stack_info"] = self.formatStack(record.stack_info)

        message = {
            key: (msg_val if (msg_val := always_fields.pop(val, None)) is not None else getattr(record, val))
            for key, val in self.fmt_keys.items()
        } | always_fields
        for key, val in record.__dict__.items():
            if key not in LOG_RECORD_BUILTIN_ATTRS:
                message[key] = serialize(val)

        return message


class NonErrorFilter(logging.Filter):
    @staticmethod
    def filter(record):
        return record.levelno <= logging.INFO


def get_logger(level="DEBUG"):
    logger = logging.getLogger(__name__)
    for handler_config in logging_config["handlers"].values():
        if (log_file := handler_config.get("filename")) is not None:
            Path(log_file).resolve().parent.mkdir(parents=True, exist_ok=True)
    logging.config.dictConfig(logging_config)
    queue_handler = logging.getHandlerByName("queue_handler")
    if queue_handler is not None:
        queue_handler.listener.start()
        atexit.register(queue_handler.listener.stop)
    logging.basicConfig(level=level)
    return logger
