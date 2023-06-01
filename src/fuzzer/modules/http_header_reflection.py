# src/fuzzer/modules/header_reflector_detector.py
import re
from bs4 import BeautifulSoup
from src.report.prepare import Prepare

class HeaderReflectorDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

        # Standard headers
        self.standard_headers = [
            'Accept', 'Accept-Charset', 'Accept-Encoding', 'Accept-Language', 'Accept-Datetime',
            'Authorization', 'Cache-Control', 'Connection', 'Cookie', 'Content-Length',
            'Content-MD5', 'Content-Type', 'Date', 'Expect', 'Forwarded', 'From',
            'Host', 'If-Match', 'If-Modified-Since', 'If-None-Match', 'If-Range',
            'If-Unmodified-Since', 'Max-Forwards', 'Origin', 'Pragma', 'Proxy-Authorization',
            'Range', 'Referer', 'TE', 'User-Agent', 'Upgrade', 'Via', 'Warning',
            'Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials',
            'Access-Control-Expose-Headers', 'Access-Control-Max-Age', 'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers', 'Accept-Ranges', 'Age', 'ETag', 'Location',
            'Proxy-Authenticate', 'Retry-After', 'Server', 'Vary', 'WWW-Authenticate',
            'X-Frame-Options', 'Public-Key-Pins', 'X-XSS-Protection', 'Content-Security-Policy',
            'X-Content-Type-Options', 'Strict-Transport-Security', 'Custom-User-Agent', 'X-Custom-Fuzz'
        ]

    def check_vulnerability(self, response, prepared_request):
        soup = BeautifulSoup(response.text, 'html.parser')
        for header, value in self.request.headers.items():
            if header not in self.standard_headers:
                header_pattern = re.compile(re.escape(value), re.IGNORECASE)
                if header_pattern.search(str(soup)):
                    result = f"Custom header {header} is reflected in the response"
                    self.logger.warning(prepared_request.url, result)
                    store_request = self.prepare._prepare_request_dict(prepared_request)
                    store_response = self.prepare._prepare_response_dict(response)
                    self.report.add_result('HeaderReflectorDetector', prepared_request.url, result, store_request, store_response)
                    break
