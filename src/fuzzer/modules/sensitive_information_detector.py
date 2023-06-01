# src/fuzzer/modules/sensitive_information_detector.py
import re
from src.report.prepare import Prepare

class SensitiveInfoDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

        """
        API keys, tokens, or credentials: For known service patterns (e.g., AWS, Google API)
        Database connection strings: For known database types (e.g., MySQL, PostgreSQL)
        Internal IP addresses: Private IP address ranges
        Cryptographic keys, certificates, or private keys: Common certificate and key headers
        """
        self.sensitive_patterns = [
            r'(?i)(?:(?:aws[_\-]?access[_\-]?key|aws[_\-]?secret[_\-]?key|google[_\-]?api[_\-]?key)[:\s]*([a-zA-Z0-9/+=]{30,}))',  # API keys
            r'(?i)(?:(?:mysql:\/\/|postgres:\/\/)[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@)',  # Database connection strings
            r'(?i)((?:10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))',  # Internal IP addresses
            r'(?i)(BEGIN (RSA|EC) PRIVATE KEY|BEGIN CERTIFICATE)',  # Cryptographic keys, certificates
        ]

    def check_vulnerability(self, response, prepared_request):
        for idx, pattern in enumerate(self.sensitive_patterns):
            sensitive_pattern = re.compile(pattern, re.IGNORECASE)
            match = sensitive_pattern.search(response.text)
            if idx == 2:  # for the internal IP addresses pattern
                # checking headers too
                for header, value in response.headers.items():
                    if sensitive_pattern.search(value):
                        match = True
                        break
            if match:
                result_messages = [
                    "API key detected",
                    "Database connection string detected",
                    "Internal IP address detected",
                    "Cryptographic key or certificate detected",
                ]
                result = result_messages[idx]
                self.logger.warning(prepared_request.url, result)
                store_request = self.prepare._prepare_request_dict(prepared_request)
                store_response = self.prepare._prepare_response_dict(response)                
                self.report.add_result('SensitiveInfoDetector', prepared_request.url, result, store_request, store_response)
                break
