# src/fuzzer/modules/http_500_detector.py
import re
from bs4 import BeautifulSoup
from src.report.prepare import Prepare

class InternalFilePathDisclosure:
    def __init__(self, request, logger, report):
        self.request = request
        self.logger = logger
        self.report = report
        self.prepare = Prepare()

    def check_vulnerability(self, response, prepared_request):

        extractPathStore = {}

        # Parse the response text using BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")

        # Remove script and style tags
        for script in soup(["script", "style"]):
            script.extract()

        # Get the cleaned response text
        cleaned_response_text = soup.get_text()


        for response_data in [str(response.headers), cleaned_response_text]:
            # Regular expressions to match various OS file paths
            path_regexes = [
                # Windows path
                r"[a-zA-Z]:\\(?:[^\\/:*?<>|\r\n]+\\)+[^\\/:*?<>|\r\n]+",
                # Unix/Linux path
                r"/(?:etc|var|usr|home|opt|root)/(?:[^/\\\0\s]+/)*[^/\\\0\s]+",
                # Mac OS X path
                r"/(?:Users|Volumes|Library|System|private|Applications)/(?:[^/\\\0\s]+/)*[^/\\\0\s]+"
            ]

            for regex in path_regexes:
                matches = re.finditer(regex, response_data)
                for match in matches:
                    path = match.group(0)
                    if not self.is_false_positive(path):
                        if path not in extractPathStore:
                            extractPathStore[path] = 1
                        else:
                            extractPathStore[path] += 1

        if extractPathStore:
            result = "Potential internal file path disclosure vulnerability"
            self.logger.critical(prepared_request.url, result)
            store_request = self.prepare._prepare_request_dict(prepared_request)
            store_response = self.prepare._prepare_response_dict(response)  
            self.report.add_result('InternalFilePathDisclosure', prepared_request.url, result, store_request, store_response)
            
    def is_false_positive(self, path):
        false_positive_patterns = [
            r"/\d+\.\d+\.\d+",  # Version numbers like /2.2.3
            r"/(?:css|js|img|fonts|images)/",  # Common static assets directories
            r"/html;",  # Part of a MIME type declaration
        ]

        for pattern in false_positive_patterns:
            if re.search(pattern, path):
                return True

        return False