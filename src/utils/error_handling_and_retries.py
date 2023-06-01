# src/utils/error_handling_and_retries.py
import time

class ErrorHandlingAndRetries:
    def __init__(self, max_retries, delay):
        self.max_retries = max_retries
        self.delay = delay

    def __call__(self, func):
        def wrapper(*args, **kwargs):
            instance = args[0]
            retries = 0
            while retries < self.max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    instance.logger.log(f"Error in {func.__name__}: {e}")
                    retries += 1
                    time.sleep(self.delay)
            instance.logger.log(f"Max retries reached for {func.__name__}")
            # Handle the failure as needed

        return wrapper

class ExceptionCounter:
    def __init__(self):
        self.throttling_errors = 0
        self.failed_requests = 0

    def increment_throttling_errors(self):
        self.throttling_errors += 1

    def increment_failed_requests(self):
        self.failed_requests += 1

    def get_throttling_errors(self):
        return self.throttling_errors

    def get_failed_requests(self):
        return self.failed_requests

    def increment(self):  
        self.increment_failed_requests()



