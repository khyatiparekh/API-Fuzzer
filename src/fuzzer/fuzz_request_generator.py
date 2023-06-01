import queue
import copy
import json
import random
import threading
from urllib.parse import urlencode, urlparse, urlunparse

class FuzzRequestGenerator:
    def __init__(self, payload_queue, pre_fuzz_request):
        self.payload_queue = payload_queue
        self.fuzz_request_queue = queue.Queue()
        self.pre_fuzz_request = pre_fuzz_request
        self.fuzz_request_queue_lock = threading.Lock()

    def get_remaining_request_count(self):
        with self.fuzz_request_queue_lock:
            return self.fuzz_request_queue.qsize()

    def generate_fuzz_requests(self):
        while not self.payload_queue.empty():
            payload_tuple = self.payload_queue.get()
            if payload_tuple is None:
                break

            method, url, request_params, context, payload_dict = payload_tuple
            payloads = json.loads(payload_dict)
                        
            # Create a copy of the pre_fuzz_request
            fuzz_request = copy.deepcopy(self.pre_fuzz_request)

            # Update the fuzz_request with the necessary information
            fuzz_request.update({
                "method": method,
                "url": url,
                "request_params": request_params,
                "context": context,
                "payloads": payloads
            })

            # Handle injection points
            injection_point = payloads.get("injection_point")
            
            if injection_point != "http_method":
                random_payload = random.choice(payloads["payload"])
            else:
                random_payload = payloads["payload"]

            if method.lower() == "get":
                if injection_point == "url_parameters":
                    url = self.add_url_params(url, request_params, random_payload)
                    fuzz_request["url"] = url
                elif injection_point == "body":
                    url = self.add_url_params(url, request_params, random_payload)
                    fuzz_request["url"] = url
                elif injection_point == "http_headers":
                    fuzz_request["headers"] = self.add_header_payloads(fuzz_request["headers"], random_payload)
                elif injection_point == "http_method":
                    fuzz_request["method"] = random_payload
            else:  # POST or other methods
                if injection_point == "url_parameters":
                    url = self.add_url_params(url, request_params, random_payload)
                    fuzz_request["url"] = url
                elif injection_point == "body":
                    fuzz_request["request_params"] = self.add_body_payloads(request_params, random_payload)
                elif injection_point == "http_headers":
                    fuzz_request["headers"] = self.add_header_payloads(fuzz_request["headers"], random_payload)
                elif injection_point == "http_method":
                    fuzz_request["method"] = random_payload

            self.fuzz_request_queue.put(fuzz_request)
        return self.fuzz_request_queue

    def add_url_params(self, url, url_params, payload):
        # Randomly select a parameter in url_params
        keys = list(url_params.keys())

        if keys:
            random_key = random.choice(keys)

            # Add payload to the randomly selected parameter
            new_params = url_params.copy()

            try:
                payload = int(payload)
                new_params[random_key] = payload
            except ValueError:
                new_params[random_key] = url_params[random_key] + payload
            
            # Update the URL with the new parameters
            url_parts = urlparse(url)
            query = urlencode(new_params)
            new_url_parts = url_parts._replace(query=query)
            new_url = urlunparse(new_url_parts)
            return new_url
        else:
            return url


    def add_header_payloads(self, headers, payload):
        # Headers usually tested during fuzzing
        fuzzable_headers = ["Host", "User-Agent", "Referer", "X-Forwarded-For", "Origin"]

        # Add payload to an existing header or a custom header
        new_headers = headers.copy()
        header_to_fuzz = random.choice(fuzzable_headers + ["custom"])
        
        if header_to_fuzz == "custom":
            new_headers[f"X-Custom-Fuzz"] = payload
        else:
            if header_to_fuzz in new_headers:
                new_headers[header_to_fuzz] += f" {payload}"
            else:
                new_headers[header_to_fuzz] = payload

        return new_headers

    def add_body_payloads(self, json_params, payload):
        # Add payload to a random parameter in json_params
        keys = list(json_params.keys())

        if keys:
            random_key = random.choice(keys)
            
            new_params = json_params.copy()

            if payload.isdigit():
                payload = int(payload)
            else:
                try:
                    payload = float(payload)
                except ValueError:
                    pass

            if isinstance(payload, int) or isinstance(payload, float):
                new_params[random_key] = payload
            else:
                new_params[random_key] += payload
            return new_params
        else:
            return json_params

    def get_next_fuzz_request(self):
        return self.fuzz_request_queue.get()

    def is_fuzz_request_queue_empty(self):
        return self.fuzz_request_queue.empty()
