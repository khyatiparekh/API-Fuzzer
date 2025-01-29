import yaml
import json

class APISpec:
    def __init__(self, api_spec_file, base_path=None):
        self.api_spec_file = api_spec_file
        self.base_path = base_path
        self.api_spec = self._load_api_spec()
        self.endpoints = self._parse_endpoints()
        # self.print_endpoints()

    def _load_api_spec(self):
        try:
            with open(self.api_spec_file, 'r', encoding='utf-8') as f:  # ✅ Set encoding to UTF-8
                if self.api_spec_file.endswith(('.yaml', '.yml')):
                    return yaml.safe_load(f)
                elif self.api_spec_file.endswith('.json'):
                    return json.load(f)
                else:
                    raise ValueError("Unsupported file format. Use YAML or JSON.")
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {self.api_spec_file}")
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ValueError(f"Error parsing API specification file: {e}")


    def _extract_parameters(self, details):
        """ Extracts both URL and Query parameters. """
        params = {"path": {}, "query": {}}
        if "parameters" in details:
            for param in details["parameters"]:
                param_type = param.get("in")
                if param_type in ["path", "query"] and "schema" in param:
                    params[param_type][param["name"]] = param["schema"].get("type", "unknown")
        return params

    def _extract_nested_json(self, schema):
        """ Recursively extracts JSON body parameters, preserving the structure. """
        if not isinstance(schema, dict):
            return "unknown"
        
        extracted = {}
        properties = schema.get("properties", {})
        for param_name, param_details in properties.items():
            param_type = param_details.get("type", "unknown")
            if param_type == "object":
                extracted[param_name] = self._extract_nested_json(param_details)
            elif param_type == "array":
                extracted[param_name] = [self._extract_nested_json(param_details.get("items", {}))]
            else:
                extracted[param_name] = param_type
        return extracted

    def _parse_json_parameters(self, details):
        """ Extracts JSON request body parameters, handling nested structures. """
        json_params = {}
        if "requestBody" in details:
            content = details["requestBody"].get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
                json_params = self._extract_nested_json(schema)
        return json_params

    def _parse_response_types(self, details):
        """ Extracts response types from the API specification. """
        responses = details.get("responses", {})
        response_types = {}
        for status_code, response in responses.items():
            content = response.get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
                response_types[status_code] = self._extract_nested_json(schema)
        return response_types

    def _parse_endpoints(self):
        """ Parses API endpoints and extracts relevant information. """
        base_path = self.base_path or self.api_spec.get('basePath', '')
        paths = self.api_spec.get('paths', {})
        endpoints = []

        for path, methods in paths.items():
            for method, details in methods.items():
                endpoint = f"{base_path}{path}"
                params = self._extract_parameters(details)
                json_params = self._parse_json_parameters(details)
                response_types = self._parse_response_types(details)
                endpoints.append((method.upper(), endpoint, params, json_params, response_types))

        return endpoints

    def get_endpoints(self):
        return self.endpoints

    def print_endpoints(self):
        """ Prints extracted API endpoint details in a structured format. """
        for method, endpoint, params, json_params, response_types in self.endpoints:
            print(f"Method: {method}")
            print(f"Endpoint: {endpoint}")
            print(f"URL Parameters: {params['path']}")
            print(f"Query Parameters: {params['query']}")
            print(f"JSON Body Parameters: {json.dumps(json_params, indent=2)}")
            print(f"Response Types: {json.dumps(response_types, indent=2)}")
            print("-" * 40)
