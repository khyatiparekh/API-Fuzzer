# fuzzer_cli.py
# python fuzzer_cli.py --api_spec ./examples/example_api_spec.yaml --threads 5 --rate 1 --timeout 10 --proxy http://127.0.0.1:8080 -b http://10.0.0.28:5000
import json
import argparse
import threading
from src.fuzzer.fuzzer import Fuzzer
from src.utils.config import Config


def parse_args():
    parser = argparse.ArgumentParser(description="API Fuzzer")

    parser.add_argument(
        "-s",
        "--api_spec",
        required=True,
        type=str,
        help="Path to the API specification file (e.g., OpenAPI or Swagger).",
    )

    parser.add_argument(
        "-b",
        "--base_path",
        type=str,
        required=True,
        help="Base path for API endpoints. Overrides the base path specified in the API specification file.",
    )
    
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Path to the fuzzer configuration file (JSON format).",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=1,
        help="Number of concurrent threads to use while fuzzing.",
    )

    parser.add_argument(
        "-r",
        "--rate",
        type=int,
        default=10,
        help="Rate limit for requests per second.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds.",
    )

    parser.add_argument(
        "--jwt",
        type=str,
        help="JWT session header. i.e Authorization: Bearer <jwt token>",
    )

    parser.add_argument(
        "--cookies",
        help="Session cookies",
    )

    parser.add_argument(
        "--headers",
        help="Custom headers. Example: header1:test1|-|header2:test2|-|header3:test3",
    )

    parser.add_argument(
        "-m",
        "--modules",
        type=str,
        nargs="*",
        help="List of module names to run. If not provided, all modules will be run. Example: BigIntegerDetector,IntegerOverflowDetector",
    )

    parser.add_argument(
        "-p",
        "--proxy",
        type=str,
        help="Proxy url",
    )
    
    return parser.parse_args()


def main():
    args = parse_args()

    # Load configuration
    config = Config()
    if args.config:
        with open(args.config, "r") as config_file:
            config_data = json.load(config_file)
            config.load(config_data)

    # Update configuration with CLI arguments
    config.update_from_args(args)

    # Initialize Fuzzer instance
    fuzzer = Fuzzer(config)

    # Run the fuzzer and interactive mode in separate threads
    fuzz_thread = threading.Thread(target=fuzzer.start)
    interactive_thread = threading.Thread(target=fuzzer.interactive_mode, args=(fuzzer,))

    fuzz_thread.start()
    interactive_thread.start()

    fuzz_thread.join()
    interactive_thread.join()

if __name__ == "__main__":
    main()
