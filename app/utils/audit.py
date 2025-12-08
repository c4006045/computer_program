import json
import logging
from datetime import datetime
from flask import request

logger = logging.getLogger("app")
def iso_now():
    return datetime.utcnow().isoformat() + "Z"
def build_payload(event: str, level: str = "INFO", user_id=None, username=None, details: dict | None = None):
    # building a payload without sensitive data
    payload = {
        "timestamp": iso_now(),
        "event": event,
        "level": level,
        "ip": request.remote_addr if request else None,
        "path": request.path if request else None,
    }
    if user_id is not None:
        payload["user_id"] = user_id
    if username is not None:
        payload["username"] = username
    if details:
        payload["details"] = details
    return payload

def log_event(event: str, level: str = "INFO",user_id=None, username=None, details: dict | None = None):
    # log event at level
    payload = build_payload(event, level, user_id, username, details)
    msg = json.dumps(payload, ensure_ascii=False)
    lvl = level.upper()
    if lvl == "DEBUG":
        logger.debug(msg)
    elif lvl == "INFO":
        logger.info(msg)
    elif lvl == "WARNING":
        logger.warning(msg)
    elif lvl == "ERROR":
        logger.error(msg)
    elif lvl == "CRITICAL":
        logger.critical(msg)
    else:
        logger.info(msg)