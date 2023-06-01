# src/fuzzer/modules/dir_traversal_detector.py
from src.report.prepare import Prepare
import re

class DirTraversalDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):
        suspicious_patterns = [
            # typical /etc/passwd entry pattern (simplified)
            r'\w+:\w*:\d+:\d+:\w*:/\w*/\w*:/\w*/\w*',
            # typical /etc/hosts entry pattern
            r'\d+\.\d+\.\d+\.\d+\s+\w+',
            # typical Windows boot.ini entry pattern (simplified)
            r'\[boot loader\].*?\[operating systems\]',
            # typical PHP error indicating an included file doesn't exist or failed to open
            r'Warning:.*include.*failed to open stream: No such file or directory',
            # PHP error indicating a failed fopen call
            r'Warning:.*fopen.*failed to open stream: No such file or directory',
            # PHP error indicating a failed require call
            r'Warning:.*require.*failed to open stream: No such file or directory',
            # PHP error indicating a function call to a non-object, potentially resulting from a null byte injection
            r'Fatal error: Call to a member function.*on a non-object in',
            # PHP error indicating potential use of a deprecated function
            r'Deprecated: Function.*is deprecated in',
            # PHP function potentially revealing sensitive data
            r'phpinfo\(',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                result = "Potential directory traversal or PHP vulnerability detected"
                self.logger.warning(prepared_request.url, result)
                store_request = self.prepare._prepare_request_dict(prepared_request)
                store_response = self.prepare._prepare_response_dict(response)
                self.report.add_result('DirTraversalDetector', prepared_request.url, result, store_request, store_response)
                break
