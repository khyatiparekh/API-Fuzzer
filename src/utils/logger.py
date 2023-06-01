# src/utils/logger.py
import logging
import os
from urllib.parse import urlparse

class Logger:
    def __init__(self):
        log_format = "[%(levelname)s] Path: %(url)-30s --> %(message)s"
        formatter = logging.Formatter(log_format)

        # Create directory for log files if it doesn't exist
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Create a file handler for logging to a file
        log_file = os.path.join(log_dir, "messages.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)

        self.logger = logging.getLogger('CustomLogger')
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    def info(self, url, message):
        truncated_url = self.truncate_url(url)
        self.logger.info(message, extra={"url": truncated_url})

    def warning(self, url, message):
        truncated_url = self.truncate_url(url)
        self.logger.warning(message, extra={"url": truncated_url})

    def error(self, url, message):
        truncated_url = self.truncate_url(url)
        self.logger.error(message, extra={"url": truncated_url})

    def critical(self, url, message):
        truncated_url = self.truncate_url(url)
        self.logger.critical(message, extra={"url": truncated_url})

    def truncate_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.path.ljust(30)
