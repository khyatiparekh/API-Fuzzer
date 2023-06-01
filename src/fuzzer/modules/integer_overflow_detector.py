# src/fuzzer/modules/integer_overflow_detector.py
import re
from src.report.prepare import Prepare
from src.utils.config import _INTEGER_TRACEBACK_PATTERNS

class IntegerOverflowDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def _generate_overflow_payloads(self):
        return [
            2**31 - 1,  # Max int32
            2**31,      # Overflow int32
            2**63 - 1,  # Max int64
            2**63,       # Overflow int64
            2**128 - 1,
            2**256 - 1,
            2**512 - 1,
            2**1024 - 1
        ]

    def check_for_overflow_payload(self, prepared_request):
        overflow_payloads = self._generate_overflow_payloads()

        # Check URL
        for payload in overflow_payloads:
            if str(payload) in prepared_request.url:
                return True

        # Check headers
        for header, value in prepared_request.headers.items():
            for payload in overflow_payloads:
                if str(payload) in str(value):
                    return True

        # Check data/body
        if prepared_request.data:
            for key, value in prepared_request.data.items():
                for payload in overflow_payloads:
                    if str(payload) in str(value):
                        return True

    def check_vulnerability(self, response, prepared_request):
        if self.check_for_overflow_payload(prepared_request) == True:
            # Check for traceback patterns
            for pattern in _INTEGER_TRACEBACK_PATTERNS:
                traceback_pattern = re.compile(pattern, re.IGNORECASE)
                if traceback_pattern.search(response.text) or response.status_code >= 500:
                    result = "Possible Integer Overflow detected"
                    self.logger.warning(prepared_request.url, result)
                    store_request = self.prepare._prepare_request_dict(prepared_request)
                    store_response = self.prepare._prepare_response_dict(response)                
                    self.report.add_result('IntegerOverflowDetector', prepared_request.url, result, store_request, store_response)
                    break