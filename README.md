# Stresstest.py - Asynchronous Network Stress Testing Tool

## Description
`stresstest.py` is a versatile asynchronous network stress testing tool designed to evaluate the performance and resilience of web servers and network services. It supports various test types including HTTP GET/POST/PUT requests, TCP connections, ICMP echo requests, and TCP SYN floods. The tool leverages `asyncio` and `aiohttp` for high-concurrency testing.

## Features
- **Configurable Parameters**: Easily adjust test parameters like target host, number of requests, and concurrency via command-line arguments.
- **HTTP Method & Payload Support**: Specify HTTP methods (GET, POST, PUT, etc.) and include custom payloads for HTTP requests.
- **Basic Reporting**: Provides a summary report after each test, including total requests, successful/failed requests, total time, and average response time.
- **Enhanced Error Handling**: For HTTP tests, a breakdown of error status codes is provided in the report.
- **Random User Agents**: Requests are sent with a rotating list of user agents to simulate diverse client traffic.
- **Multiple Test Types**:
    - **HTTP**: Stress test web servers with configurable methods and payloads.
    - **TCP**: Test raw TCP connection handling.
    - **ICMP**: Perform basic ping-like tests.
    - **SYN Flood**: Simulate a SYN flood attack (requires root/sudo for raw sockets).

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
usage: stresstest.py [-h] --test_type {http,tcp,icmp,syn} --target_host TARGET_HOST [--target_port TARGET_PORT] [--num_requests NUM_REQUESTS] [--concurrency CONCURRENCY] [--method METHOD] [--payload PAYLOAD] [--verbose]

Asynchronous Network Test Script

options:
  -h, --help            show this help message and exit
  --test_type {http,tcp,icmp,syn}
                        Type of test to perform
  --target_host TARGET_HOST
                        Target URL (for HTTP) or IP address (for TCP, ICMP, SYN)
  --target_port TARGET_PORT
                        Target port (for TCP and SYN)
  --num_requests NUM_REQUESTS
                        Number of requests or connections to send
  --concurrency CONCURRENCY
                        Number of concurrent requests or connections
  --method METHOD       HTTP method for HTTP tests (e.g., GET, POST, PUT)
  --payload PAYLOAD     Payload for HTTP POST/PUT requests
  --verbose             Enable verbose logging
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
