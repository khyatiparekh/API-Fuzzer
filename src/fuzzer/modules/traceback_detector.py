# src/fuzzer/modules/traceback_detector.py
import re
from src.report.prepare import Prepare
from src.utils.config import _TRACEBACK_PATTERNS

class TracebackDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):
        for pattern in _TRACEBACK_PATTERNS:
            traceback_pattern = re.compile(pattern, re.IGNORECASE)
            if traceback_pattern.search(response.text):
                if response.status_code != 500:
                    result = "Traceback or error detected but Status code is NOT 500"
                else:
                    result = "Traceback or error detected"

                result = "Traceback or error detected"
                self.logger.warning(prepared_request.url, result)
                store_request = self.prepare._prepare_request_dict(prepared_request)
                store_response = self.prepare._prepare_response_dict(response)                
                self.report.add_result('TracebackDetector', prepared_request.url, result, store_request, store_response)
                break
