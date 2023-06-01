# src/fuzzer/modules/http_500_detector.py
from src.report.prepare import Prepare

class HTTP502Detector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):
        if response.status_code == 502:
            result = "HTTP 502 error"
            self.logger.warning(prepared_request.url, result)
            store_request = self.prepare._prepare_request_dict(prepared_request)
            store_response = self.prepare._prepare_response_dict(response)            
            self.report.add_result('HTTP502Detector', prepared_request.url, result, store_request, store_response)
