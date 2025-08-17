# Stresstest.py - Asynchronous Network Stress Testing Tool

## Description
`stresstest.py` is a versatile asynchronous network stress testing tool designed to evaluate the performance and resilience of web servers and network services. It supports various test types including HTTP GET/POST/PUT requests, TCP connections, ICMP echo requests, and TCP SYN floods. The tool leverages `asyncio` and `aiohttp` for high-concurrency testing.

## Features
- **Configurable Parameters**: Easily adjust test parameters like target host, number of requests, and concurrency via command-line arguments.
- **Duration-based Testing**: Run tests for a specified duration rather than a fixed number of requests.
- **HTTP Method & Payload Support**: Specify HTTP methods (GET, POST, PUT, etc.) and include custom payloads for HTTP requests.
- **Custom Request Headers**: Add arbitrary HTTP headers to your requests.
- **Detailed Reporting**: Generate comprehensive reports in console, CSV, or JSON formats.
- **Enhanced Error Handling**: For HTTP tests, a breakdown of error status codes is provided in the report.
- **Random User Agents**: Requests are sent with a rotating list of user agents to simulate diverse client traffic.
- **Multiple Test Types**:
    - **HTTP**: Stress test web servers with configurable methods and payloads.
    - **TCP**: Test raw TCP connection handling.
    - **ICMP**: Perform basic ping-like tests.
    - **SYN Flood**: Simulate a SYN flood attack (requires root/sudo for raw sockets).
    - **UDP**: Send UDP packets to a target host and port.

## Installation
To run `stresstest.py`, you need Python 3.7+ and the following libraries:

```bash
pip install aiohttp scapy
```

**Note**: For ICMP and SYN flood tests, `scapy` requires raw socket access, which typically means running the script with `sudo` or appropriate permissions.

## Usage

```bash
python stresstest.py --help
```

```
usage: stresstest.py [-h] --test_type {http,tcp,icmp,syn,udp} --target_host TARGET_HOST [--target_port TARGET_PORT] [--num_requests NUM_REQUESTS] [--duration DURATION] [--concurrency CONCURRENCY] [--method METHOD] [--payload PAYLOAD] [--headers HEADERS] [--verbose] [--output_format {console,csv,json}] [--output_file OUTPUT_FILE]

Asynchronous Network Test Script

options:
  -h, --help            show this help message and exit
  --test_type {http,tcp,icmp,syn,udp}
                        Type of test to perform
  --target_host TARGET_HOST
                        Target URL (for HTTP) or IP address (for TCP, ICMP, SYN, UDP)
  --target_port TARGET_PORT
                        Target port (for TCP, SYN, and optional for HTTP, UDP)
  --num_requests NUM_REQUESTS
                        Number of requests or connections to send (ignored if --duration is set)
  --duration DURATION   Duration of the test in seconds (overrides --num_requests)
  --concurrency CONCURRENCY
                        Number of concurrent requests or connections
  --method METHOD       HTTP method for HTTP tests (e.g., GET, POST, PUT)
  --payload PAYLOAD     Payload for HTTP POST/PUT requests
  --headers HEADERS     Custom HTTP headers in key:value;key2:value2 format
  --verbose             Enable verbose logging
  --output_format {console,csv,json}
                        Output format for the report
  --output_file OUTPUT_FILE
                        File path to save the report
```

## Examples

### HTTP GET Request
Perform 100 HTTP GET requests to example.com with 10 concurrent connections.
```bash
python stresstest.py --test_type http --target_host https://example.com --num_requests 100 --concurrency 10
```

### HTTP POST Request with Payload
Send 50 HTTP POST requests to an API endpoint with a JSON payload, 5 concurrent connections.
```bash
python stresstest.py --test_type http --target_host https://api.example.com/data --num_requests 50 --concurrency 5 --method POST --payload '{"key": "value"}'
```

### TCP Connection Test
Establish 200 TCP connections to a server on port 8080 with 20 concurrent connections.
```bash
python stresstest.py --test_type tcp --target_host 192.168.1.1 --target_port 8080 --num_requests 200 --concurrency 20
```

### ICMP Echo Test (Ping)
Send 10 ICMP echo requests to a host.
```bash
sudo python stresstest.py --test_type icmp --target_host 8.8.8.8 --num_requests 10
```

### TCP SYN Flood (Requires sudo)
Send 500 TCP SYN packets to a target on port 80.
```bash
sudo python stresstest.py --test_type syn --target_host 192.168.1.100 --target_port 80 --num_requests 500
```

### UDP Packet Test
Send 100 UDP packets to a target on port 1234 with 10 concurrent connections.
```bash
python stresstest.py --test_type udp --target_host 192.168.1.100 --target_port 1234 --num_requests 100 --concurrency 10
```
