import itertools
import random
import string
import base64
from src.utils.config import (_INTERESTING_DATES, _INTERESTING_INTS, _INTERESTING_STRS,
                              _CRLF_INJECTION, _DIR_TRAVERSAL, _FORMAT_STR, _OPEN_REDIRECT, 
                              _JSON, _NULL_BYTE, _XML_PAYLOADS, _HTML_INJECTION)

class PayloadGenerator:
    def __init__(self, context_payloads):
        self.context_payloads = context_payloads
        self.injection_points = ['url_parameters', 'http_method', 'http_headers', 'body']
        self.interesting_dates = _INTERESTING_DATES
        self.interesting_integers = _INTERESTING_INTS
        self.interesting_strings = _INTERESTING_STRS
        self.all_http_methods = [
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "OPTIONS",
            "HEAD",
            "CONNECT",
            "TRACE",
            "METHODACTING"
        ]

    def apply_random_mutation(self, payload, context):
        payload = str(payload)
        mutator = random.choice(self.context_payloads[context]["mutators"])
        return mutator(self, payload)

    def generate_payloads(self, context, max_combinations=None):
        payload_types = self.context_payloads.get(context, [])

        if not payload_types:
            return []

        combined_payloads = itertools.product(*[getattr(self, pt) for pt in payload_types["payload_types"]])

        # Calculate the cartesian product length
        product_length = 1
        for pt in payload_types["payload_types"]:
            product_length *= len(getattr(self, pt))

        if max_combinations is not None:
            # Get a random sample of indices
            indices = random.sample(range(product_length), min(max_combinations, product_length))
            indices_set = set(indices)

            # Create a separate function that yields elements from combined_payloads with the selected indices
            def sampled_product(combined_payloads, indices_set):
                for i, item in enumerate(combined_payloads):
                    if i in indices_set:
                        yield item

            combined_payloads = sampled_product(combined_payloads, indices_set)

        def payload_generator():
            combined_payloads_list = list(combined_payloads)
            generated_payloads = []

            for combination in combined_payloads_list:
                mutated_payloads = tuple(self.apply_random_mutation(payload, context) for payload in combination)
                injection_point = random.choice(self.injection_points)

                if "http_method" not in injection_point:
                    generated_payloads.append({
                        'type': context,
                        'payload': mutated_payloads,
                        'injection_point': injection_point
                    })

            for combination in combined_payloads_list:
                for method in self.all_http_methods:
                    generated_payloads.append({
                        'type': context,
                        'payload': method,
                        'injection_point': "http_method"
                    })

            additional_payloads = self.context_payloads.get(context, {}).get("additional_payloads", {})
            num_additional_payloads = product_length

            total_additional_payloads_generated = 0

            for payload_type, payload_info in additional_payloads.items():
                num_injection_points = len(payload_info["injection_points"])
                payloads_per_injection_point = num_additional_payloads // num_injection_points

                for injection_point in payload_info["injection_points"]:
                    if total_additional_payloads_generated >= num_additional_payloads:
                        break

                    selected_payloads = random.sample(payload_info["payloads"], min(payloads_per_injection_point, len(payload_info["payloads"])))
                    for payload in selected_payloads:
                        generated_payloads.append({
                            'type': context,
                            'payload': payload,
                            'injection_point': injection_point
                        })
                        total_additional_payloads_generated += 1
                        if total_additional_payloads_generated >= num_additional_payloads:
                            break

            return generated_payloads
        return payload_generator()

    def mutate_length(self, payload, min_len=0, max_len=100):
        new_len = random.randint(min_len, max_len)
        return payload[:new_len] + "".join(random.choices(string.printable, k=new_len - len(payload)))

    def mutate_character_substitution(self, payload):
        if not payload:
            return payload
        
        index = random.randint(0, len(payload) - 1)
        new_char = random.choice(string.printable)
        return payload[:index] + new_char + payload[index + 1:]

    def mutate_case_transformation(self, payload):
        if random.choice([True, False]):
            return payload.lower()
        else:
            return payload.upper()

    def mutate_encoding(self, payload):
        if random.choice([True, False]):
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload.encode('utf-16').decode('ISO-8859-1')

    def mutate_number(self, payload):
        numbers = list(map(str, self.interesting_integers))
        return str(random.choice(numbers))

    def mutate_format_string(self, payload):
        format_strings = ["%s", "%x", "%d", "%u", "%f", "%n"]
        index = random.randint(0, len(payload))
        new_format_string = random.choice(format_strings)
        return payload[:index] + new_format_string + payload[index:]

    def count_payloads(self, context):
        payload_types_dict = self.context_payloads.get(context, {})
        if not payload_types_dict:
            return 0

        payload_types = payload_types_dict.get("payload_types", [])
        return len(list(itertools.product(*[getattr(self, pt) for pt in payload_types])))

    def generate_value(self, param_type):
        if param_type == "string":
            length = random.randint(1, 20)
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        elif param_type == "integer":
            return random.randint(-10000, 10000)
        elif param_type == "boolean":
            return random.choice([True, False])
        elif param_type == "float":
            return random.uniform(-10000, 10000)
        elif param_type == "list" or param_type == "array":
            list_length = random.randint(1, 10)
            return [self.generate_value("string") for _ in range(list_length)]
        else:
            return "unknown_type"


payload_lists = {
    "dates": "interesting_dates",
    "integers": "interesting_integers",
    "strings": "interesting_strings",
    "methods": "all_http_methods"
}

context_payloads = {
    "json": {
        "payload_types": [payload_lists["dates"], payload_lists["integers"], payload_lists["strings"]],
        "mutators": [
            PayloadGenerator.mutate_length,
            PayloadGenerator.mutate_character_substitution,
            PayloadGenerator.mutate_case_transformation,
            PayloadGenerator.mutate_encoding,
            PayloadGenerator.mutate_number,
            PayloadGenerator.mutate_format_string
        ],
        "additional_payloads": {
            "CRLF_injection": {
                "payloads": _CRLF_INJECTION,
                "injection_points": ["url_parameters", "http_headers"]
            },
            "dir_traversal": {
                "payloads": _DIR_TRAVERSAL,
                "injection_points": ["url_parameters", "body"]
            },
            "format_str": {
                "payloads": _FORMAT_STR,
                "injection_points": ["url_parameters", "body"]
            },
            "open_redirect": {
                "payloads": _OPEN_REDIRECT,
                "injection_points": ["url_parameters", "body"]
            },
            "json_payloads": {
                "payloads": _JSON,
                "injection_points": ["body"]
            },
            "null_byte_representations": {
                "payloads": _NULL_BYTE,
                "injection_points": ["url_parameters", "body"]
            }
        }
    },
    "xml": {
        "payload_types": [payload_lists["dates"], payload_lists["integers"], payload_lists["strings"]],
        "mutators": [
            PayloadGenerator.mutate_length,
            PayloadGenerator.mutate_character_substitution,
            PayloadGenerator.mutate_case_transformation,
            PayloadGenerator.mutate_encoding,
            PayloadGenerator.mutate_number,
            PayloadGenerator.mutate_format_string
        ],
        "additional_payloads": {
            "CRLF_injection": {
                "payloads": _CRLF_INJECTION,
                "injection_points": ["url_parameters", "http_headers"]
            },
            "dir_traversal": {
                "payloads": _DIR_TRAVERSAL,
                "injection_points": ["url_parameters"]
            },
            "format_str": {
                "payloads": _FORMAT_STR,
                "injection_points": ["url_parameters", "body"]
            },
            "open_redirect": {
                "payloads": _OPEN_REDIRECT,
                "injection_points": ["url_parameters", "body"]
            },
            "null_byte_representations": {
                "payloads": _NULL_BYTE,
                "injection_points": ["url_parameters", "body"]
            },
            "xml_payloads": {
                "payloads": _XML_PAYLOADS,
                "injection_points": ["body"]
            }
        }
    },
    "html": {
        "payload_types": [payload_lists["dates"], payload_lists["integers"], payload_lists["strings"]],
        "mutators": [
            PayloadGenerator.mutate_length,
            PayloadGenerator.mutate_character_substitution,
            PayloadGenerator.mutate_case_transformation,
            PayloadGenerator.mutate_encoding,
            PayloadGenerator.mutate_number,
            PayloadGenerator.mutate_format_string
        ],
        "additional_payloads": {
            "CRLF_injection": {
                "payloads": _CRLF_INJECTION,
                "injection_points": ["url_parameters", "http_headers"]
            },
            "dir_traversal": {
                "payloads": _DIR_TRAVERSAL,
                "injection_points": ["url_parameters", "body"]
            },
            "format_str": {
                "payloads": _FORMAT_STR,
                "injection_points": ["url_parameters", "body"]
            },
            "open_redirect": {
                "payloads": _OPEN_REDIRECT,
                "injection_points": ["url_parameters", "body"]
            },
            "json_payloads": {
                "payloads": _JSON,
                "injection_points": ["body"]
            },
            "null_byte_representations": {
                "payloads": _NULL_BYTE,
                "injection_points": ["url_parameters", "body"]
            },
            "html_injection": {
                "payloads": _HTML_INJECTION,
                "injection_points": ["url_parameters", "body"]
            }
        }
    },
    "unknown": {
        "payload_types": [payload_lists["dates"], payload_lists["integers"], payload_lists["strings"]],
        "mutators": [
            PayloadGenerator.mutate_length,
            PayloadGenerator.mutate_character_substitution,
            PayloadGenerator.mutate_case_transformation,
            PayloadGenerator.mutate_encoding,
            PayloadGenerator.mutate_number,
            PayloadGenerator.mutate_format_string
        ],
        "additional_payloads": {
            "CRLF_injection": {
                "payloads": _CRLF_INJECTION,
                "injection_points": ["url_parameters", "http_headers"]
            },
            "dir_traversal": {
                "payloads": _DIR_TRAVERSAL,
                "injection_points": ["url_parameters", "body"]
            },
            "format_str": {
                "payloads": _FORMAT_STR,
                "injection_points": ["url_parameters", "body"]
            },
            "open_redirect": {
                "payloads": _OPEN_REDIRECT,
                "injection_points": ["url_parameters", "body"]
            },
            "json_payloads": {
                "payloads": _JSON,
                "injection_points": ["body"]
            },
            "null_byte_representations": {
                "payloads": _NULL_BYTE,
                "injection_points": ["url_parameters", "body"]
            },
            "html_injection": {
                "payloads": _HTML_INJECTION,
                "injection_points": ["url_parameters", "body"]
            }
        }
    }
}

