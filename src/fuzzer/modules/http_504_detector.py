# src/fuzzer/modules/http_500_detector.py
from src.report.prepare import Prepare

class HTTP504Detector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):
        if response.status_code == 504:
            result = "HTTP 504 error"
            self.logger.warning(prepared_request.url, result)
            store_request = self.prepare._prepare_request_dict(prepared_request)
            store_response = self.prepare._prepare_response_dict(response)            
            self.report.add_result('HTTP504Detector', prepared_request.url, result, store_request, store_response)
