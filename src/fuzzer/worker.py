# src/fuzzer/worker.py
import re
import copy
import time
import json
import chardet
import urllib3
import statistics
import threading
import requests
import http.client
from src.utils.logger import Logger
from collections import Counter
from urllib.parse import urlparse, urlencode
from src.utils.error_handling_and_retries import ExceptionCounter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ExceptionHandling:
    def __init__(self, exception_counter, on_exception=None):
        self.exception_counter = exception_counter
        self.on_exception = on_exception
        self.count = 0
        
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.exception_counter.increment()
            if self.on_exception:
                self.on_exception(exc_type, exc_val, exc_tb)
        return True
    
    def increment(self):
        self.count += 1


class HTTPClientPreparedRequest:
    def __init__(self, method, url, headers, body=None):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body

    def __str__(self):
        headers_str = "\n".join([f"{k}: {v}" for k, v in self.headers.items()])
        return f'<HTTPClientPreparedRequest [{self.method}] {self.url}\nHeaders:\n{headers_str}\nBody:\n{self.body}>'

    
class Worker(threading.Thread):
    total_workers = 0
    paused_workers = 0
    pause_lock = threading.Lock()
    stopped_workers = 0
    stop_lock = threading.Lock()
    response_times = []

    def __init__(self, fuzzer, active_requests_semaphore, worker_done_event):
        super().__init__()
        self.fuzzer = fuzzer
        self.active_requests_semaphore = active_requests_semaphore
        self.exception_counter = ExceptionCounter()
        self.successful_requests = 0
        self.failed_requests = 0
        Worker.total_workers += 1
        self.logger = Logger()
        self.worker_done_event = worker_done_event
        self.stop_requested = threading.Event()  # Add a stop_requested event


    @classmethod
    def all_workers_paused(cls):
        with cls.pause_lock:
            return cls.paused_workers == cls.total_workers
        
    @classmethod
    def all_workers_stopped(cls):
        with cls.stop_lock:
            return cls.stopped_workers == cls.total_workers
        
    def log_failed_request(self, url, exc_type, exc_val, exc_tb):
        with self.fuzzer.failed_requests_lock:
            self.fuzzer.failed_requests += 1
        self.failed_requests += 1
        self.logger.error(url, f"Error sending request: {exc_val}")

    def stop(self):  # Add a stop method to signal the thread to stop
        self.stop_requested.set()

    def run(self):
        # Worker starts
        #with self.fuzzer._cookie_update_lock:
        #s    fuzz_request = self.fuzzer.pre_fuzz_request.copy()

        while not self.fuzzer.stop_event.is_set() and not self.stop_requested.is_set():  # Check for stop_requested flag
            if not self.fuzzer.pause:
                self._fuzz()
            else:
                while self.fuzzer.pause and not self.fuzzer.stop_event.is_set():
                    time.sleep(1)  # Sleep for a short duration before checking the pause and stop states again

        with Worker.stop_lock:  # Acquire the stop_lock
            Worker.stopped_workers += 1  # Increment the stopped_workers counter

        """
        # Print statistics about response times when the worker finishes
        if len(Worker.response_times) > 0:
            average_time = statistics.mean(Worker.response_times)
            median_time = statistics.median(Worker.response_times)
            std_dev_time = statistics.stdev(Worker.response_times) if len(Worker.response_times) > 1 else 0
            print(f"\nWorker {self.ident} finished. Response times (ms): Average={average_time:.2f}, Median={median_time:.2f}, StdDev={std_dev_time:.2f}\n")
        """
            
    def _fuzz(self):
        while not self.fuzzer.fuzz_request_generator.is_fuzz_request_queue_empty():
            
            if self.fuzzer.pause or self.fuzzer.stop_event.is_set():
                Worker.paused_workers += 1
                break

            with self.fuzzer.semaphore:
                fuzz_request = self.fuzzer.fuzz_request_generator.get_next_fuzz_request()
                if fuzz_request is None:  # Stop the worker if it encounters the sentinel value (None)
                    break
                method = fuzz_request["method"]
                url = fuzz_request["url"]
                headers = fuzz_request["headers"]
                request_params = fuzz_request["request_params"]
                payloads = fuzz_request["payloads"]
                timeout = fuzz_request["timeout"]
                proxies = fuzz_request["proxies"]

                response, prepared_request = self._send_request(url, method, headers, request_params, payloads, timeout, proxies)
                
                if response == None or prepared_request == None:
                    continue

                for module in self.fuzzer.modules:
                    with ExceptionHandling(self.exception_counter):
                        module.check_vulnerability(response, prepared_request)

                # Update the progress bar
                self.fuzzer.update_progress_bar()
                # Increment the successful_requests counter
                self.successful_requests += 1

    def _send_request(self, url, method, headers, request_params, payloads, timeout, proxies):
        def clean_header_value(value):
            # Remove specific problematic characters from the header value
            return re.sub(r'[\x00-\x1F\x7F\r\n\'"]', '', value)
        
        response = None
        prepared_request = None        
        session = requests.Session()
        
        pre_fuzz_request = copy.deepcopy(self.fuzzer.pre_fuzz_request)

        # Clean the header values
        cleaned_headers = {k: clean_header_value(v) for k, v in headers.items()}
        pre_fuzz_request['headers'].update(cleaned_headers)

        # Initialize encoding with a default value
        encoding = 'utf-8'

        if "injection_point" in payloads and (payloads["injection_point"] == "body" or payloads["injection_point"] == "url_parameters"):
            # Detect the encoding of the parameter payload and set the Content-Type header accordingly
            detected_encoding = chardet.detect(json.dumps(request_params).encode())['encoding']
            encoding = detected_encoding if detected_encoding is not None else 'utf-8'
        elif "injection_point" in payloads and payloads["injection_point"] == "http_headers":
            header_encodings = {}
            for header_key, header_value in headers.items():
                detected_header_encoding = chardet.detect(header_value.encode())['encoding']
                header_encodings[header_key] = detected_header_encoding if detected_header_encoding is not None else 'utf-8'

            most_common_encoding = Counter(header_encodings.values()).most_common(1)[0][0]

            # Initialize payload_encoding with the most_common_encoding
            payload_encoding = most_common_encoding

            for header_key, header_value in headers.items():
                if header_encodings[header_key] != most_common_encoding:
                    payload_header_key = header_key
                    payload_encoding = header_encodings[header_key]
                    break
            encoding = payload_encoding

        pre_fuzz_request['headers']['Content-Type'] = f'application/json; charset={encoding}'

        if 'timeout' in pre_fuzz_request:
            del pre_fuzz_request['timeout']
        if 'proxies' in pre_fuzz_request:
            del pre_fuzz_request['proxies']

        if "injection_point" in payloads and payloads["injection_point"] == "body":
            request = requests.Request(method, url, json=request_params, **pre_fuzz_request)
        else:
            request = requests.Request(method, url, params=request_params, **pre_fuzz_request)

        try:
            with ExceptionHandling(self.exception_counter, on_exception=lambda exc_type, exc_val, exc_tb: self.log_failed_request(url, exc_type, exc_val, exc_tb)):
                if self.fuzzer.stop_event.is_set():  # Check the stop_event before sending the request
                    return None, None
                
                # Encode headers and request parameters using the detected encoding with error handling
                encoded_headers = {k: v.encode(encoding, errors='replace').decode('latin1') for k, v in request.headers.items()}
                request.headers.update(encoded_headers)

                if request.params:
                    encoded_params = {k: v.encode(encoding, errors='replace').decode('latin1') for k, v in request.params.items()}
                    request.params.update(encoded_params)

                prepared_request = request.prepare()

                if self.fuzzer.stop_event.is_set():  # Check the stop_event after sending the request
                    return None, None
                
                start_time = time.perf_counter()
                # Pass the 'timeout' and 'proxies' parameters to the session.send() method
                response = session.send(prepared_request, timeout=timeout, proxies=proxies, verify=False)
                end_time = time.perf_counter()
                elapsed_time = (end_time - start_time) * 1000
                Worker.response_times.append(elapsed_time)
                time.sleep(0.2)
        except Exception as e:
            with ExceptionHandling(self.exception_counter, on_exception=lambda exc_type, exc_val, exc_tb: self.log_failed_request(url, exc_type, exc_val, exc_tb)):
                # If there is an error with the requests module, try using the http.client module
                response, prepared_request = self._send_request_using_httpclient(url, method, headers, request_params, payloads, timeout, proxies, encoding)
                
        return response, prepared_request

    def _send_request_using_httpclient(self, url, method, headers, request_params, payloads, timeout, proxies, encoding):
        # Parse the URL to extract the host, port, and path
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port or (80 if parsed_url.scheme == 'http' else 443)
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query

        # Check if a proxy is provided
        proxy_url = proxies.get(parsed_url.scheme) if proxies else None
        if proxy_url:
            parsed_proxy_url = urlparse(proxy_url)
            proxy_host = parsed_proxy_url.hostname
            proxy_port = parsed_proxy_url.port or 8080

            # Create a connection object with the proxy host and port
            if parsed_url.scheme == 'http':
                connection = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
            else:
                connection = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout)

            # Set up the tunnel through the proxy to the target server
            connection.set_tunnel(host, port)

        else:
            # Create a connection object without a proxy
            if parsed_url.scheme == 'http':
                connection = http.client.HTTPConnection(host, port, timeout=timeout)
            else:
                connection = http.client.HTTPSConnection(host, port, timeout=timeout)

        # Encode headers using the detected encoding
        encoded_headers = {k: v.encode(encoding).decode('latin1') for k, v in headers.items()}

        # Check if the payload injection point is in the request_params
        if "injection_point" in payloads and payloads["injection_point"] == "url_parameters":
            encoded_params = {k: v.encode(encoding).decode('latin1') for k, v in request_params.items()}
            path += '?' + urlencode(encoded_params)

        with ExceptionHandling(self.exception_counter, on_exception=lambda exc_type, exc_val, exc_tb: self.log_failed_request(parsed_url, exc_type, exc_val, exc_tb)):
            # Send the request
            connection.request(method, path, headers=encoded_headers)

            start_time = time.perf_counter()
            response = connection.getresponse()
            end_time = time.perf_counter()
            elapsed_time = (end_time - start_time) * 1000
            Worker.response_times.append(elapsed_time)

            # Read the response and convert it to a requests.Response object
            response_content = response.read()
            response_headers = dict(response.getheaders())

            response_obj = requests.Response()
            response_obj.status_code = response.status
            response_obj.reason = response.reason
            response_obj.url = url
            response_obj.headers = response_headers
            response_obj._content = response_content

            # Close the connection
            connection.close()

            # Create an HTTPClientPreparedRequest instance
            http_client_prepared_request = HTTPClientPreparedRequest(method, url, encoded_headers, body=None)
            time.sleep(0.2)

            return response_obj, http_client_prepared_request
           
