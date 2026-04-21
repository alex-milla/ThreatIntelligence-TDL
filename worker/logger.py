#!/usr/bin/env python3
"""Logging setup with 90-day rotation."""

import logging
import os
from logging.handlers import TimedRotatingFileHandler


def setup_logger(log_dir: str = "./logs") -> logging.Logger:
    """Configure rotating file logger (90 days) + console output."""
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("tdl_worker")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # File handler: rotate every midnight, keep 90 days
    file_handler = TimedRotatingFileHandler(
        os.path.join(log_dir, "worker.log"),
        when="midnight",
        interval=1,
        backupCount=90,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(console_handler)

    return logger
