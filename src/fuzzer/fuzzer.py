# src/fuzzer/fuzzer.py
import inspect
import json
import keyboard
import threading
import time
import requests
import importlib
import os
import queue
import copy
import pkgutil
from termcolor import colored
from tabulate import tabulate
from tqdm import tqdm
from threading import Lock
from threading import Semaphore
from contextlib import contextmanager
from requests.structures import CaseInsensitiveDict
from src.fuzzer.api_spec import APISpec
from src.utils.logger import Logger
from src.fuzzer.worker import Worker
from src.report.report import Report
from src.utils.error_handling_and_retries import ExceptionCounter
from src.fuzzer.response_analyzer import ResponseAnalyzer
from src.fuzzer.payload_generator import PayloadGenerator, context_payloads
from src.fuzzer.fuzz_request_generator import FuzzRequestGenerator
from src.fuzzer.jwt_payload_configuration import check_jwt_configuration

commands = {
    colored("Pause", 'light_magenta'): "ctrl+p",
    colored("Resume", 'green'): "ctrl+p",
    colored("Kill", 'red'): "ctrl+k"
}

@contextmanager
def keyboard_interrupt_handler(fuzzer):
    try:
        yield
    except KeyboardInterrupt:
        print(colored("\n[-] Gracefully stopping the fuzzer...", 'red'))
        fuzzer.stop_event.set()
        fuzzer.worker_done_event.set()
        for worker in fuzzer.workers:
            worker.join()

class Fuzzer:
    def __init__(self, config):
        self.config = config
        self.api_spec = APISpec(self.config['api_spec'], base_path=self.config.get("base_path"))
        self.pre_fuzz_request = None
        self.logger = Logger()
        self.endpoints = self.api_spec.get_endpoints()
        self.report_instance = Report()
        self.modules = self._load_modules()
        self.exception_counter = ExceptionCounter()
        self.stop_event = threading.Event()
        self.pause = False
        self.stop = False
        self.payload_queue = queue.Queue()
        self.response_analyzer = ResponseAnalyzer()
        self._initialize_pre_fuzz_request()
        self.payload_generator = PayloadGenerator(context_payloads)
        self.semaphore = Semaphore(5)
        self.failed_requests = 0
        self.failed_requests_lock = threading.Lock()
        self.workers = []
        self.progress_bar_lock = Lock()
        self.worker_done_event = threading.Event()        


    def _initialize_pre_fuzz_request(self):
        headers = CaseInsensitiveDict()
        headers["Custom-User-Agent"] = "KhadakSingh API Fuzzer"

        if self.config.get("jwt"):
            headers["Authorization"] = f"Bearer {self.config['jwt']}"
        elif self.config.get("cookies"):
            headers["Cookie"] = self.config['cookies']

        if self.config.get("headers"):
            headers_list = self.config["headers"].split('|-|')

            for header in headers_list:
                key, value = header.split(':')
                headers[key] = value
                            
        self.pre_fuzz_request = {
            "headers": headers,
            "timeout": self.config["timeout"],
        }

        # Add proxy to the pre_fuzz_request if it's configured
        if "proxy" in self.config and self.config["proxy"]:
            self.pre_fuzz_request["proxies"] = {
                "http": self.config["proxy"],
                "https": self.config["proxy"],
            }

    def _load_modules(self):
        all_modules = []
        package = 'src.fuzzer.modules'
        path = os.path.join('src', 'fuzzer', 'modules')

        for (_, module_name, _) in pkgutil.iter_modules([path]):
            module = importlib.import_module(f"{package}.{module_name}")
            for _, class_obj in inspect.getmembers(module, inspect.isclass):
                if module.__name__ == class_obj.__module__:
                    all_modules.append(class_obj(self.pre_fuzz_request, self.logger, self.report_instance))

        # If modules are specified in the configuration, filter the loaded modules
        if "modules" in self.config and self.config["modules"]:
            if "," in self.config["modules"][0]:
                selected_modules = self.config["modules"][0].split(",")
                selected_modules = set(selected_modules)
            else:
                selected_modules = set(self.config["modules"])
            all_modules = [module for module in all_modules if module.__class__.__name__ in selected_modules]
        else:
            selected_modules = "All"

        print(colored(f"\n[#] Configured modules", 'cyan'))

        if isinstance(selected_modules, str):
            print(colored("     All", 'light_magenta'))
        else:
            for modules in selected_modules:
                print(colored(f"     {modules}", 'light_magenta'))

        return all_modules

    def toggle_pause(self):
        self.pause = not self.pause

    def progress_bar_to_dict(self, progress_bar):
        format_dict = progress_bar.format_dict
        return {
            "elapsed": format_dict['elapsed'],
            "remaining": int(format_dict['total']) - int(format_dict['elapsed']),
            "total": format_dict['total'],
            "n": format_dict['n'],
            "rate": format_dict['rate'],
        }

    def display_scan_status(self, scan_status):

        progress_bar_dict = self.progress_bar_to_dict(self.progress_bar)

        with self.failed_requests_lock:
            failed_requests_count = self.failed_requests

        elapsed_time = progress_bar_dict['elapsed']
        remaining_time = progress_bar_dict['remaining']
        total_requests = progress_bar_dict['total']
        requests_completed = progress_bar_dict['n']
        tps = progress_bar_dict['rate']

        if scan_status == "paused":
            print(colored("\n\n[*] Fuzzing process", 'light_magenta'), colored(f"{scan_status}", 'light_yellow'))

            print(colored("\n[*] Current Scan Status:", 'light_magenta'))
            print(f"----> Elapsed Time: {elapsed_time}")
            print(f"----> Requests Completed: {requests_completed}")
            print(f"----> Failed Requests: {failed_requests_count}")
            print(f"----> Transactions per Second (tps): {tps}\n")
        elif scan_status == "resumed":
            pass
        elif scan_status == "stopped":
            print(colored("\n\n[*] Fuzzing process", 'light_magenta'), colored(f"{scan_status}", 'red'))

            print(colored("\n[*] Scan Status:", 'light_magenta'))
            print(f"----> Total Time: {elapsed_time}")
            print(f"----> Requests Completed: {requests_completed}")
            print(f"----> Failed Requests: {failed_requests_count}")
            print(f"----> Transactions per Second (tps): {tps}")            

    def is_fuzzing_done(self):
        return self.worker_done_event.is_set()

    @staticmethod
    def interactive_mode(fuzzer):
        def toggle_on_ctrl_p():
            fuzzer.toggle_pause()
            pause_resume = "paused" if fuzzer.pause else "resumed"
            
            if pause_resume == "paused":
                while not Worker.all_workers_paused():
                    time.sleep(0.1)

                fuzzer.display_scan_status("paused")
            else:
                fuzzer.display_scan_status("resumed")

        def stop_on_ctrl_k():
            fuzzer.stop_event.set()

            while not Worker.all_workers_stopped():
                time.sleep(0.1)
            
            fuzzer.display_scan_status("stopped")

        keyboard.add_hotkey("ctrl+p", toggle_on_ctrl_p, suppress=False)
        keyboard.add_hotkey("ctrl+k", stop_on_ctrl_k, suppress=True)

        while not fuzzer.stop_event.is_set() and not fuzzer.is_fuzzing_done():
            time.sleep(1)

    def get_next_request(self, url, method, url_params=None, json_params=None):
        request = copy.deepcopy(self.pre_fuzz_request)
        if url_params is None:
            url_params = {}
        if json_params is None:
            json_params = {}

        request["method"] = method
        request["url"] = url
        request["url_params"] = url_params
        request["json_params"] = json_params

        return request

    def send_request(self, request):
        method = request.get("method", "GET").upper()
        response = None

        try:
            if method == "GET":
                response = requests.get(request["url"], headers=request["headers"], timeout=request["timeout"], proxies=request.get("proxies"), allow_redirects=False, verify=False)
            elif method == "POST":
                response = requests.post(request["url"], headers=request["headers"], timeout=request["timeout"], proxies=request.get("proxies"), allow_redirects=False, verify=False)

        except Exception as e:
            self.fuzzer.logger.error(request["url"], f"Error sending request: {e}")
            self.exception_counter.increment()
            return -1  # Return -1 when there's a connection issue

        return response

    def update_progress_bar(self):
        with self.progress_bar_lock:
            self.progress_bar.update(1)
            
    def all_workers_done(self):
        for worker in self.workers:
            if worker.is_alive():
                return False
        return True

    def start(self):
        print(colored("\n\n[#] Commands and Shortcuts", "cyan"))
        print(tabulate(commands.items(), headers=[colored("Commands:", 'cyan'), colored("Shortcut:", 'cyan')], tablefmt="pipe"))

        if self.config.get("jwt"):
            check_jwt_configuration(self.config["jwt"])

        total_endpoints = len(self.endpoints)
        print(colored(f"\n\n[#] Starting Fuzzing on {total_endpoints} endpoints...", 'cyan'))

        # Start the payload producer thread
        payload_producer = PayloadProducer(self)
        payload_producer.start()

        # Wait for the payload producer to finish
        payload_producer.join()

        # Instantiate and start the fuzz request generator
        self.fuzz_request_generator = FuzzRequestGenerator(self.payload_queue, self.pre_fuzz_request)
        fuzz_request_queue = self.fuzz_request_generator.generate_fuzz_requests()
        
        print(colored("\n[*] Fuzzing progress", 'light_magenta'))

        # Create a new progress bar with the total length of the fuzz request queue
        self.progress_bar = tqdm(total=fuzz_request_queue.qsize(), desc="")

        # Start worker threads
        for _ in range(self.config["threads"]):
            worker = Worker(self, self.semaphore, self.worker_done_event)
            worker.start()
            self.workers.append(worker)

        try:
            # Continue checking if all workers are done
            while not self.all_workers_done():
                if fuzz_request_queue.qsize() == 0:
                    # If fuzz request queue is empty, stop the workers
                    for worker in self.workers:
                        worker.stop()

                time.sleep(1)

        except KeyboardInterrupt:
            # Handle user interruption and stop the workers
            print(colored("\n[-] Interrupted by user. Stopping workers...", 'red'))

            for worker in self.workers:
                worker.stop()

        finally:
            # Signal workers to stop by setting the worker_done_event
            self.worker_done_event.set()
            print(colored("\n\n[#] Done\n", 'cyan'))

        # Wait for all workers to finish
        for worker in self.workers:
            worker.join()

        output_formats = ['json', 'text', 'html']
        output_folder = "reports"  

        # Create the output folder if it does not exist
        os.makedirs(output_folder, exist_ok=True)

        print(colored(f"\n[#] Saving Reports\n", 'cyan'))
        for output_format in output_formats:
            report_content = self.report_instance.generate_report(output_format=output_format)
            output_filename = f"{output_folder}/report_{output_format}.{output_format}"
            if output_format == "html":
                with open(output_filename, 'w', encoding='utf-8') as output_file:
                    output_file.write(report_content)
            else:
                with open(output_filename, 'w') as output_file:
                    output_file.write(report_content)

            print(colored(f"[*] Report saved in {output_format} format: {output_filename}", 'green'))
        
        # Remove payload temporary file
        os.remove("my_set.txt")

        # Remove the keyboard listener
        keyboard.unhook_all()

class PayloadProducer(threading.Thread):
    def __init__(self, fuzzer):
        super().__init__()
        self.fuzzer = fuzzer
        self.response_analyzer = ResponseAnalyzer()

    def run(self):
        total_payloads = 0

        # Limit the number of payloads per context
        max_payloads_per_context = 200  

        unique_payloads = set()

        print(colored("\n[*] Generating Payloads", 'light_magenta'))

        with tqdm(total=len(self.fuzzer.endpoints), desc="") as progress_bar:
            for method, url, url_params, json_params in self.fuzzer.endpoints:
                try:
                    # Get the next request to send
                    request = self.fuzzer.get_next_request(url, method, url_params, json_params)

                    # Send the request and get the response
                    response = self.fuzzer.send_request(request)

                    if response is None or response == -1:
                        if response == -1:
                            print(colored("\n[-] Connection issue detected. Pausing the fuzzer", 'red'))
                            self.fuzzer.toggle_pause()
                        else:
                            self.fuzzer.logger.error(url, f"No response received for {url}. Skipping this endpoint.")
                        continue
                    
                    # Analyze the response to determine its context
                    self.response_analyzer.analyze_response(response)

                    most_common_context = max(set(self.response_analyzer.contexts), key=self.response_analyzer.contexts.count)

                    # Count the number of payloads for the most common context
                    payloads_count = self.fuzzer.payload_generator.count_payloads(most_common_context)
                    total_payloads += min(payloads_count, max_payloads_per_context)

                    # Generate payloads for the most common context
                    payload_dicts = self.fuzzer.payload_generator.generate_payloads(most_common_context, max_payloads_per_context)

                    for payload_dict in payload_dicts[:max_payloads_per_context]:
                        # Add URL parameters to the payload
                        formatted_url = url
                        for param_name, param_type in url_params.items():
                            param_value = self.fuzzer.payload_generator.generate_value(param_type)  # Generate the parameter value
                            formatted_url = formatted_url.replace('{' + param_name + '}', param_value)

                        # Add JSON parameters to the payload
                        payload_json = {}
                        for param_name, param_type in json_params.items():
                            param_value = self.fuzzer.payload_generator.generate_value(param_type)  # Generate the parameter value
                            payload_json[param_name] = param_value
                            
                        payload_json_str = json.dumps(payload_json, sort_keys=True)
                        payload_dict_str = json.dumps(payload_dict, sort_keys=True) 
                        payload_tuple = (method, formatted_url, payload_json_str, most_common_context, payload_dict_str)
                        unique_payloads.add(payload_tuple)  # Add the payload tuple to the set of unique payloads

                    progress_bar.update(1)
                except Exception as e:
                    self.fuzzer.logger.error(url, f"Error in payload production: {e}")
                    self.fuzzer.exception_counter.increment()

        # Open a file for writing
        with open('my_set.txt', 'w') as file:
            file.write(str(unique_payloads))
            
        # Replace the original queue with a new queue containing unique payloads
        self.fuzzer.payload_queue = queue.Queue()
        for payload_tuple in unique_payloads:
            self.fuzzer.payload_queue.put((payload_tuple[0], payload_tuple[1], json.loads(payload_tuple[2]), payload_tuple[3], payload_tuple[4]))

        self.fuzzer.payload_queue.put(None)  # Signal that payload generation is done
