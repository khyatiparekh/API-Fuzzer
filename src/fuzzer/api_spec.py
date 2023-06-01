import yaml
import json

class APISpec:
    def __init__(self, api_spec_file, base_path=None):
        self.api_spec_file = api_spec_file
        self.base_path = base_path
        self.api_spec = self._load_api_spec()
        self.endpoints = self._parse_endpoints()

    def _load_api_spec(self):
        with open(self.api_spec_file, 'r') as f:
            if self.api_spec_file.endswith('.yaml') or self.api_spec_file.endswith('.yml'):
                return yaml.safe_load(f)
            elif self.api_spec_file.endswith('.json'):
                return json.load(f)
            else:
                raise ValueError("Unsupported API specification file format. Supported formats are YAML and JSON.")

    def _parse_url_parameters(self, details):
        url_params = {}
        if "parameters" in details:
            for param in details["parameters"]:
                if param["in"] == "path":
                    url_params[param["name"]] = param["schema"]["type"]
        return url_params

    def _parse_json_parameters(self, details):
        json_params = {}
        if "requestBody" in details:
            content = details["requestBody"]["content"]
            if "application/json" in content:
                schema = content["application/json"]["schema"]
                if "properties" in schema:
                    for param_name, param_details in schema["properties"].items():
                        json_params[param_name] = param_details["type"]
        return json_params

    def _parse_endpoints(self):
        base_path = self.base_path or self.api_spec.get('basePath', '')
        paths = self.api_spec.get('paths', {})
        endpoints = []

        for path, methods in paths.items():
            for method, details in methods.items():
                endpoint = f"{base_path}{path}"
                url_params = self._parse_url_parameters(details)
                json_params = self._parse_json_parameters(details)
                endpoints.append((method, endpoint, url_params, json_params))

        return endpoints

    def get_endpoints(self):
        return self.endpoints
