import queue
import copy
import json
import random
import re
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

class FuzzRequestGenerator:
    def __init__(self, payload_queue, pre_fuzz_request):
        self.payload_queue = payload_queue
        self.fuzz_request_queue = queue.Queue()
        self.pre_fuzz_request = pre_fuzz_request
        self.fuzz_request_queue_lock = threading.Lock()

    def generate_fuzz_requests(self):
        while not self.payload_queue.empty():
            payload_tuple = self.payload_queue.get()
            if payload_tuple is None:
                break

            method, url, request_params, context, payload_dict = payload_tuple
            payloads = json.loads(payload_dict)
            fuzz_request = copy.deepcopy(self.pre_fuzz_request)
            fuzz_request.update({
                "method": method,
                "url": url,
                "request_params": request_params,
                "context": context,
                "payloads": payloads
            })
            injection_point = payloads.get("injection_point")
            random_payload = random.choice(payloads["payload"]) if injection_point != "http_method" else payloads["payload"]

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
            else:
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
        """ Properly injects fuzzing payloads into URL parameters. """
        keys = list(url_params.keys())

        if keys:
            random_key = random.choice(keys)
            new_params = url_params.copy()

            try:
                payload = int(payload)  # Attempt to convert payload to an integer
                new_params[random_key] = payload
            except ValueError:
                # Ensure url_params[random_key] is a string before concatenation
                if isinstance(url_params[random_key], list):
                    new_params[random_key] = url_params[random_key] + [str(payload)]
                else:
                    new_params[random_key] = str(url_params[random_key]) + str(payload)

            # Update the URL with the new parameters
            url_parts = urlparse(url)
            query = urlencode(new_params, doseq=True)  # doseq=True ensures lists are encoded correctly
            new_url_parts = url_parts._replace(query=query)
            new_url = urlunparse(new_url_parts)
            return new_url

        return url


    def add_header_payloads(self, headers, payload):
        """ Properly injects payloads into headers while maintaining required formats. """

        # Headers usually tested during fuzzing
        fuzzable_headers = ["Host", "User-Agent", "Referer", "X-Forwarded-For", "Origin"]

        # Copy existing headers to avoid modifying the original
        new_headers = headers.copy()
        header_to_fuzz = random.choice(fuzzable_headers + ["custom"])

        # Define format rules for specific headers
        def format_payload(header, value):
            """ Ensures payload format is valid for the given header. """
            if header == "Host":
                return f"{value}.evil.com"  # Ensure payload looks like a subdomain
            elif header == "Origin":
                return f"https://{value}.evil.com"  # Ensure it remains a valid origin URL
            elif header == "Referer":
                return f"https://{value}/ref"  # Ensure it follows a valid referer format
            elif header == "X-Forwarded-For":
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):  # Ensure it's an IP
                    return value  # Keep IP as is
                else:
                    return f"192.168.1.1, {value}"  # Simulate chained IPs
            elif header == "User-Agent":
                return f"{value}"  # Append to a valid User-Agent
            return value  # Default: return payload as is

        if header_to_fuzz == "custom":
            new_headers[f"X-Custom-Fuzz"] = payload
        else:
            formatted_payload = format_payload(header_to_fuzz, payload)

            if header_to_fuzz in new_headers:
                new_headers[header_to_fuzz] += f" {formatted_payload}"
            else:
                new_headers[header_to_fuzz] = formatted_payload

        return new_headers


    def add_body_payloads(self, json_params, payload):
        """ Recursively injects a fuzzing payload into a randomly selected parameter in nested JSON. """

        def inject_payload(data, depth=0, max_depth=7):
            """ Prevents infinite recursion by limiting depth. """
            if depth > max_depth:
                return payload  # Stop recursion at max depth

            if isinstance(data, dict) and data:  # If it's a non-empty dictionary
                random_key = random.choice(list(data.keys()))
                data[random_key] = inject_payload(data[random_key], depth + 1, max_depth)
                return data
            
            elif isinstance(data, list) and data:  # If it's a non-empty list
                random_index = random.randint(0, len(data) - 1)
                data[random_index] = inject_payload(data[random_index], depth + 1, max_depth)
                return data
            
            else:  # Inject payload directly
                if isinstance(data, (int, float)):
                    return str(data) + str(payload)  # Convert numbers to strings and append payload
                elif isinstance(data, str):
                    return data + str(payload)  # Append payload to strings
                else:
                    return payload  # Replace null/unknown values with payload

        return inject_payload(json_params)



    def get_next_fuzz_request(self):
        return self.fuzz_request_queue.get()

    def is_fuzz_request_queue_empty(self):
        return self.fuzz_request_queue.empty()
