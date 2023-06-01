# API Fuzzer

This is a comprehensive, feature-rich API Fuzzer designed to help discover potential vulnerabilities in your application.
Features:

    Pause, Stop, Resume functionality: Control your fuzzing sessions with ease.

    Payload Generator: Generate a diverse range of payloads using various methods.
        Random Payload Generator based on Interesting Strings, Dates, Integers.
        Payload Mutators: Modify payloads to cover edge cases, including Integer, Format Strings, Encoding, Case Transformation, Character Substitution, and Length adjustments.
        Additional Payloads: Generate payloads specific to common vulnerabilities/fuzzing including CRLF Injection, Directory Traversal, Format String, Open Redirect, JSON Fuzzing, Null Byte Representations, XML Payloads, and HTML Injection.
    
    Injection Points: Target HTTP Headers, HTTP Method, URL, and Body with your payloads.

    Custom inputs: Supports Custom Headers and Cookies

    Reporting: Generates detailed reports in text, JSON, or HTML format, which can be helpful in understanding and reproducing vulnerabilities.

## Usage

To use the fuzzer, simply call the main CLI file with the appropriate options.

```python fuzzer_cli.py --api_spec ./examples/example_api_spec.yaml --threads 5 --rate 1 --timeout 10 --proxy http://127.0.0.1:8080 -b http://10.0.0.28:5000```

### Here's a brief rundown of the options:

    -s / --api_spec - (Required) Path to the API specification file (e.g., OpenAPI or Swagger).
    -b / --base_path - (Required) Base path for API endpoints. Overrides the base path specified in the API specification file.
    -c / --config - Path to the fuzzer configuration file (JSON format).
    -t / --threads - Number of concurrent threads to use while fuzzing.
    -r / --rate - Rate limit for requests per second.
    --timeout - Request timeout in seconds.
    --jwt - JWT session cookie.
    --cookies - Session cookies.
    --headers - Custom headers. Example: header1:test1,header2:test2,header3:test3.
    -m / --modules - List of module names to run. If not provided, all modules will be run. Example: BigIntegerDetector,IntegerOverflowDetector.
    -p / --proxy - Proxy URL.


## Report Generation

The fuzzer includes a reporting feature that outputs in text, JSON, or HTML format. These reports are generated as findings are detected in real time and provide detailed information about each request made during the session, including:

    The name of the module that generated the payload.
    The endpoint that was targeted.
    The result of the request (e.g., whether a potential vulnerability was found).
    The full details of the request and the response.

The HTML report is particularly useful, as it groups the requests by module and endpoint, and allows you to inspect each request and response in detail.

## Requirements

    Python 3.8 or later

## Installation

To install, clone the repository and install the required packages:

sh

git clone https://github.com/yourusername/fuzzer.git
cd fuzzer
pip install -r requirements.txt

## Reporting Bugs/Issues

If you encounter any bugs or issues, feel free to open an issue on the GitHub repository.

## Contributing

Contributions are welcome! Please open a pull request with your changes or new features.

## License

This project is licensed under the MIT License. For more information, please see the LICENSE file.
