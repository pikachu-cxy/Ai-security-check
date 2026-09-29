import json
import logging
import os
import sys

LOG_LEVELS = {"ERROR", "WARNING", "INFO", "DEBUG"}


def mcp_log_level() -> str:
    level = os.getenv("SECURITY_RUNTIME_LOG_LEVEL", "WARNING").upper()
    if level not in LOG_LEVELS:
        raise ValueError("SECURITY_RUNTIME_LOG_LEVEL must be ERROR, WARNING, INFO, or DEBUG")
    return level


class SafeJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "event": record.msg, "scan_id": getattr(record, "scan_id", ""), "mode": getattr(record, "mode", ""), "duration_ms": getattr(record, "duration_ms", 0)}, ensure_ascii=False)


def configure_logging(*, mcp: bool = False) -> None:
    if not mcp and os.getenv("SECURITY_RUNTIME_LOG_JSON") != "1":
        return
    handler = logging.StreamHandler(sys.stderr)
    if os.getenv("SECURITY_RUNTIME_LOG_JSON") == "1":
        handler.setFormatter(SafeJSONFormatter())
    logger = logging.getLogger("security_runtime")
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(mcp_log_level() if mcp else logging.INFO)
    if mcp:
        logger.propagate = False
