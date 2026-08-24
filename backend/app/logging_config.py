"""Logging configuration and utilities."""
import logging
import json
from pythonjsonlogger import jsonlogger
from app.config import settings


def setup_logging():
    """Configure structured JSON logging."""
    logger = logging.getLogger()
    
    # JSON formatter for structured logs
    json_formatter = jsonlogger.JsonFormatter(
        '%(timestamp)s %(level)s %(name)s %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(json_formatter)
    logger.addHandler(console_handler)
    
    # Set log level
    log_level = getattr(logging, settings.log_level, logging.INFO)
    logger.setLevel(log_level)
    
    return logger


logger = setup_logging()
