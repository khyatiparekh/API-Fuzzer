class ResponseAnalyzer:
    def __init__(self):
        self.contexts = []

    def analyze_response(self, response):
        # Analyze the response to determine its context
        content_type = response.headers.get("Content-Type", "").lower()

        if "json" in content_type:
            self.contexts.append("json")
        elif "xml" in content_type:
            self.contexts.append("xml")
        elif "html" in content_type:
            self.contexts.append("html")
        else:
            self.contexts.append("unknown")
