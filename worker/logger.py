#!/usr/bin/env python3
"""Logging setup with 90-day rotation."""

import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler


def setup_logger(log_dir: str = "./logs") -> logging.Logger:
    """Configure rotating file logger (90 days) + console output."""
    log_dir = os.path.abspath(log_dir)
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, "worker.log")

    # Touch the file to ensure it exists and we have permissions
    try:
        with open(log_path, "a", encoding="utf-8"):
            pass
    except OSError as e:
        print(f"[-] Cannot create log file {log_path}: {e}", file=sys.stderr)

    logger = logging.getLogger("tdl_worker")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # File handler: rotate every midnight, keep 90 days
    try:
        file_handler = TimedRotatingFileHandler(
            log_path,
            when="midnight",
            interval=1,
            backupCount=90,
            encoding="utf-8",
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"[-] Failed to setup file handler: {e}", file=sys.stderr)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    logger.addHandler(console_handler)

    return logger
