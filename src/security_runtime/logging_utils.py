import json
import logging
import os
import sys


class SafeJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "event": record.msg, "scan_id": getattr(record, "scan_id", ""), "mode": getattr(record, "mode", ""), "duration_ms": getattr(record, "duration_ms", 0)}, ensure_ascii=False)


def configure_logging() -> None:
    if os.getenv("SECURITY_RUNTIME_LOG_JSON") != "1":
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(SafeJSONFormatter())
    logger = logging.getLogger("security_runtime")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
