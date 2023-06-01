import json
import os
import base64
import html
from urllib.parse import urlparse
from threading import Lock

class Report:
    def __init__(self):
        self.results = []
        self.lock = Lock()

    def add_result(self, module_name, endpoint, result, request_dict, response_dict):
        with self.lock:
            self.results.append({
                'module_name': module_name,
                'endpoint': endpoint,
                'result': result,
                'request': request_dict,
                'response': response_dict
            })

    def get_results(self):
        with self.lock:
            return self.results.copy()

    def generate_report(self, output_format='text'):
        if output_format == 'text':
            return self._generate_text_report()
        elif output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'html':
            return self._generate_html_report()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _convert_bytes_to_str(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        if isinstance(obj, list):
            return [self._convert_bytes_to_str(item) for item in obj]
        if isinstance(obj, dict):
            return {key: self._convert_bytes_to_str(value) for key, value in obj.items()}
        return obj

    def _generate_text_report(self):
        report = []
        for result in self.get_results():
            report.append(f"{result['module_name']} - {result['endpoint']}: {result['result']}\nRequest: {result['request']}\nResponse: {result['response']}\n")
        return "\n".join(report)

    def _generate_json_report(self):
        converted_results = self._convert_bytes_to_str(self.get_results())
        return json.dumps(converted_results, indent=2)
        
    def _generate_html_report(self):
        # Load HTML template from file
        template_path = os.path.join(os.getcwd(), 'src', 'report', 'report_template.html')

        with open(template_path, 'r') as template_file:
            html_template = template_file.read()

        # Generate report data
        report_data = self.get_results()

        # Group report data by module name
        modules = {}
        for result in report_data:
            module_name = result['result']
            if module_name not in modules:
                modules[module_name] = []
            modules[module_name].append(result)

        # Create collapsible sections for each module
        module_sections = ""
        for module_name, module_results in modules.items():
            url_sections = ""
            seen_urls = {}  # Track URLs and their methods
            for result in module_results:
                url = urlparse(result['endpoint']).scheme + "://" + urlparse(result['endpoint']).netloc + urlparse(result['endpoint']).path
                method = result['request']['method']
                if url not in seen_urls:
                    seen_urls[url] = {method: [result]}
                else:
                    if method not in seen_urls[url]:
                        seen_urls[url][method] = [result]
                    else:
                        seen_urls[url][method].append(result)

            for url, methods in seen_urls.items():
                url_section = ""
                counter = 1
                for method, results in methods.items():
                    for result in results:
                        request_table = self._generate_html_table(result['request'])
                        # Encode the HTML content to base64
                        request_table_base64 = base64.b64encode(request_table.encode()).decode()

                        response_table = self._generate_html_table(result['response'])
                        # Encode the HTML content to base64
                        response_table_base64 = base64.b64encode(response_table.encode()).decode()

                        # Generate HTML with tabs for each request
                        url_section += f"""
                        <button class='btn' onclick="showModal('{request_table_base64}', '{response_table_base64}')">Request {counter}: {url} ({method})</button>
                        <div id='myModal' class='modal'>
                            <!-- Modal content -->
                            <div class='modal-content'>
                                <span class='close'>&times;</span>
                                <div class='row'>
                                    <div class='column'>
                                        <div class='tab'>
                                            <button class='tablinks' onclick="openTab(event, 'Request')">
                                                Request
                                            </button>
                                            <button class='tablinks' onclick="openTab(event, 'Response')">
                                                Response
                                            </button>
                                        </div>
                                        <div id='Request' class='tabcontent'>
                                            <h3>Requests</h3>
                                            <div id='modalRequestTable'></div>
                                        </div>
                                        <div id='Response' class='tabcontent'>
                                            <h3>Responses</h3>
                                            <div id='modalResponseTable'></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        """
                        counter += 1

                url_section += """<button class='btn1'></button>"""
                url_sections += url_section
                
            module_section = f"""
            <button class='collapsible'>{module_name}</button>
            <div class='collapsible-content'>
                <div class='btn-container'>
                    {url_sections}
                </div>
            </div>
            """

            module_sections += module_section

        # Replace placeholder in HTML template
        html_report = html_template.replace('[MODULE_SECTIONS]', module_sections)

        return html_report

    def _generate_html_table(self, data):
        table = "<table>"
        for key, value in data.items():
            key = html.escape(key)
            if isinstance(value, str):
                try:
                    json_value = json.loads(value)
                    pretty_json_value = json.dumps(json_value, indent=4)
                    value = f"<pre>{html.escape(pretty_json_value)}</pre>"
                except json.JSONDecodeError:
                    value = html.escape(value)
            else:
                value = html.escape(str(value))

            if isinstance(value, bytes):
                value = value.decode('UTF-8')

            table += f"<tr><td>{key}</td><td><pre>{value}</pre></td></tr>"
        table += "</table>"
        return table
