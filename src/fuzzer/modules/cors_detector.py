# src/fuzzer/modules/cors_detector.py
import re
from src.report.prepare import Prepare

class CORSDetector:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):
        """Check if CORS vulnerabilities exist based on the Origin header."""
        origin_sent = prepared_request.headers.get("Origin")

        # Only proceed if the Origin header was in the request
        if not origin_sent:
            return

        cors_issues = []

        # Extract relevant CORS headers from the response
        access_control_origin = response.headers.get("Access-Control-Allow-Origin", "")
        access_control_credentials = response.headers.get("Access-Control-Allow-Credentials", "")

        # Case 1: Access-Control-Allow-Origin reflects the request Origin (Potential Reflection Issue)
        if access_control_origin == origin_sent:
            cors_issues.append("Origin header reflected in Access-Control-Allow-Origin, potential CORS bypass")

        # Case 2: Wildcard (*) in Access-Control-Allow-Origin
        if access_control_origin == "*":
            cors_issues.append("Wildcard (*) used in Access-Control-Allow-Origin")

        # Case 3: Wildcard (*) with Access-Control-Allow-Credentials: true (Major Security Issue)
        if access_control_origin == "*" and access_control_credentials.lower() == "true":
            cors_issues.append("Access-Control-Allow-Credentials is TRUE while Access-Control-Allow-Origin is *, critical security misconfiguration")

        # Case 4: Access-Control-Allow-Origin allowing multiple arbitrary origins
        if re.match(r"^https?://.*", access_control_origin) and "*" in access_control_origin:
            cors_issues.append("Access-Control-Allow-Origin contains an arbitrary wildcard, possible misconfiguration")

        # Log and Report CORS issues
        if cors_issues:
            for issue in cors_issues:
                self.logger.warning(prepared_request.url, issue)

            store_request = self.prepare._prepare_request_dict(prepared_request)
            store_response = self.prepare._prepare_response_dict(response)
            self.report.add_result('CORSDetector', prepared_request.url, ", ".join(cors_issues), store_request, store_response)
