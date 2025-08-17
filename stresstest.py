#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import random
import logging
import socket
from aiohttp import ClientError, ClientSession
from scapy.all import sr1, IP, ICMP, TCP, send
from urllib.parse import urlparse

# ASCII Art Section
try:
    with open("ascii_art.txt", "r") as f:
        ASCII_ART = f.read()
except FileNotFoundError:
    ASCII_ART = r"""


 ____   ___  ____      _____           _     ____          
|  _ \ / _ \/ ___|    |_   _|__   ___ | |   | __ ) _   _ _ 
| | | | | | \___ \ _____| |/ _ \ / _ \| |   |  _ \| | | (_)
| |_| | |_| |___) |_____| | (_) | (_) | |_  | |_) | |_| |_ 
|____/ \___/|____/      |_|\___/ \___/|_( ) |____/ \__, (_)
 ____                                   |/  _   _  |___/   
|  _ \  ___   __ _  ___ _ __ ___   __ _| |_| |_(_)         
| | | |/ _ \ / _` |/ _ \ '_ ` _ \ / _` | __| __| |         
| |_| | (_) | (_| |  __/ | | | | | (_| | |_| |_| |         
|____/ \___/ \__, |\___|_| |_| |_|\__,_|\__|\__|_|         
             |___/                                         


"""
print(ASCII_ART)

# User Agents List
user_agents = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Mobile Safari/537.36",
]

# Configure logging
logger = logging.getLogger(__name__)


def configure_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def get_random_user_agent():
    return random.choice(user_agents)


import time

async def fetch_url(session: ClientSession, url: str, headers: dict, results: list, method: str, payload: str = None):
    start_time = time.time()
    try:
        async with session.request(method, url, headers=headers, data=payload) as response:
            logger.info(f"Request to {url} returned {response.status}")
            await response.read()
            if response.status >= 400:
                results.append({"success": False, "status": response.status, "time": time.time() - start_time})
            else:
                results.append({"success": True, "status": response.status, "time": time.time() - start_time})
    except ClientError as e:
        logger.error(f"Request to {url} failed: {e}")
        results.append({"success": False, "error": str(e), "time": time.time() - start_time})


async def async_https_get_request(target_url, num_requests, headers, concurrency, method: str, payload: str = None, duration: int = None):
    results = []
    async with ClientSession() as session:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = set()
        start_time = time.time()

        if duration:
            while True:
                elapsed_time = time.time() - start_time
                if elapsed_time >= duration:
                    break
                task = asyncio.create_task(fetch_url_with_semaphore(session, target_url, headers, semaphore, results, method, payload))
                tasks.add(task)
                # Remove completed tasks to prevent memory leak
                tasks = {t for t in tasks if not t.done()}
                await asyncio.sleep(0.001) # Small sleep to prevent busy-waiting
        else:
            for _ in range(num_requests):
                task = asyncio.create_task(fetch_url_with_semaphore(session, target_url, headers, semaphore, results, method, payload))
                tasks.add(task)

        # Wait for all remaining tasks to complete
        if tasks:
            await asyncio.gather(*tasks)
    return results

async def fetch_url_with_semaphore(session: ClientSession, url: str, headers: dict, semaphore: asyncio.Semaphore, results: list, method: str, payload: str = None):
    async with semaphore:
        await fetch_url(session, url, headers, results, method, payload)


async def async_tcp_test(target_host, target_port, num_connections, concurrency, duration: int = None):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    tasks = set()
    start_time = time.time()

    if duration:
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time >= duration:
                break
            task = asyncio.create_task(tcp_connection_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)
            tasks = {t for t in tasks if not t.done()}
            await asyncio.sleep(0.001)
    else:
        for _ in range(num_connections):
            task = asyncio.create_task(tcp_connection_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)

    if tasks:
        await asyncio.gather(*tasks)
    return results

async def tcp_connection_with_semaphore(target_host, target_port, semaphore: asyncio.Semaphore, results: list):
    async with semaphore:
        await tcp_connection(target_host, target_port, results)


async def tcp_connection(target_host, target_port, results: list):
    start_time = time.time()
    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
        logger.info(f"Connected to TCP {target_host}:{target_port}")
        writer.close()
        await writer.wait_closed()
        results.append({"success": True, "time": time.time() - start_time})
    except Exception as e:
        logger.error(f"TCP connection to {target_host}:{target_port} failed: {e}")
        results.append({"success": False, "error": str(e), "time": time.time() - start_time})


def send_icmp_echo(target_host, num_requests):
    for _ in range(num_requests):
        packet = IP(dst=target_host) / ICMP()
        resp = sr1(packet, timeout=1, verbose=0)
        if resp:
            logger.info(f"ICMP Reply from {target_host}: {resp.summary()}")
        else:
            logger.info(f"No ICMP Reply from {target_host}")


def send_tcp_syn(target_host, target_port, num_requests):
    for _ in range(num_requests):
        syn_packet = IP(dst=target_host) / TCP(dport=target_port, flags="S")
        resp = sr1(syn_packet, timeout=1, verbose=0)
        if resp and resp.getlayer(TCP).flags & 0x12:  # SYN/ACK flags
            logger.info(f"Received SYN/ACK from {target_host}:{target_port}")
            # Properly tear down the connection by sending a RST packet
            rst_packet = IP(dst=target_host) / TCP(
                dport=target_port, flags="R", seq=resp.ack
            )
            send(rst_packet, verbose=0)
        else:
            logger.info(f"No SYN/ACK from {target_host}:{target_port}")


def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False


def validate_ip(ip_address):
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error as e:
        logger.error(f"IP validation error: {e}")
        return False


def parse_custom_headers(headers_string):
    headers = {}
    if headers_string:
        pairs = headers_string.split(';')
        for pair in pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers

def parse_args():
    parser = argparse.ArgumentParser(description="Asynchronous Network Test Script")
    parser.add_argument("--test_type", required=True, choices=["http", "tcp", "icmp", "syn"], help="Type of test to perform")
    parser.add_argument("--target_host", required=True, help="Target URL (for HTTP) or IP address (for TCP, ICMP, SYN)")
    parser.add_argument("--target_port", type=int, help="Target port (for TCP, SYN, and optional for HTTP)")
    parser.add_argument("--num_requests", type=int, default=1, help="Number of requests or connections to send (ignored if --duration is set)")
    parser.add_argument("--duration", type=int, help="Duration of the test in seconds (overrides --num_requests)")
    parser.add_argument("--concurrency", type=int, default=1, help="Number of concurrent requests or connections")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method for HTTP tests (e.g., GET, POST, PUT)")
    parser.add_argument("--payload", type=str, help="Payload for HTTP POST/PUT requests")
    parser.add_argument("--headers", type=str, help="Custom HTTP headers in key:value;key2:value2 format")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--output_format", type=str, choices=["console", "csv", "json"], default="console", help="Output format for the report")
    parser.add_argument("--output_file", type=str, help="File path to save the report")
    return parser.parse_args()


import json
import csv

def generate_and_print_report(results: list, test_type: str, output_format: str = "console", output_file: str = None):
    total_requests = len(results)
    successful_requests = sum(1 for r in results if r["success"])
    failed_requests = total_requests - successful_requests
    total_time = sum(r["time"] for r in results)
    average_time = total_time / total_requests if total_requests > 0 else 0

    report_data = {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "total_time": total_time,
        "average_response_time": average_time,
    }

    if test_type == "HTTP" and failed_requests > 0:
        status_code_counts = {}
        for r in results:
            if not r["success"] and "status" in r:
                status_code_counts[r["status"]] = status_code_counts.get(r["status"], 0) + 1
        if status_code_counts:
            report_data["http_error_status_code_breakdown"] = status_code_counts

    if output_format == "console":
        print(f"\n--- {test_type} Test Report ---")
        print(f"Total Requests: {report_data["total_requests"]}")
        print(f"Successful Requests: {report_data["successful_requests"]}")
        print(f"Failed Requests: {report_data["failed_requests"]}")

        if "http_error_status_code_breakdown" in report_data:
            print("\nHTTP Error Status Code Breakdown:")
            for status_code, count in sorted(report_data["http_error_status_code_breakdown"].items()):
                print(f"  Status {status_code}: {count} requests")

        print(f"Total Time: {report_data["total_time"]:.2f} seconds")
        print(f"Average Response Time: {report_data["average_response_time"]:.4f} seconds")
        print("---------------------------")
    elif output_file:
        try:
            with open(output_file, 'w') as f:
                if output_format == "json":
                    json.dump(report_data, f, indent=4)
                elif output_format == "csv":
                    # For CSV, we'll simplify and just write the main stats
                    # More complex CSV for status codes would require more logic
                    writer = csv.writer(f)
                    writer.writerow(["Metric", "Value"])
                    for key, value in report_data.items():
                        if isinstance(value, dict): # Skip nested dicts for simple CSV
                            continue
                        writer.writerow([key, value])
            logger.info(f"Report saved to {output_file} in {output_format} format.")
        except IOError as e:
            logger.error(f"Could not write report to file {output_file}: {e}")

async def main():

    args = parse_args()
    configure_logging(args.verbose)
    headers = {"User-Agent": get_random_user_agent()}
    if args.headers:
        custom_headers = parse_custom_headers(args.headers)
        headers.update(custom_headers)

    print(ASCII_ART)

    if args.test_type == "http":
        if args.target_port:
            # Construct URL with port if provided
            parsed_url = urlparse(args.target_host)
            netloc_with_port = f"{parsed_url.hostname}:{args.target_port}"
            args.target_host = parsed_url._replace(netloc=netloc_with_port).geturl()

        if not validate_url(args.target_host):
            logger.error("Invalid URL format.")
            return
        results = await async_https_get_request(args.target_host, args.num_requests, headers, args.concurrency, args.method, args.payload, args.duration)
        generate_and_print_report(results, "HTTP", args.output_format, args.output_file)
    elif args.test_type == "tcp":
        if not validate_ip(args.target_host):
            logger.error("Invalid IP address format.")
            return
        results = await async_tcp_test(args.target_host, args.target_port, args.num_requests, args.concurrency, args.duration)
        generate_and_print_report(results, "TCP", args.output_format, args.output_file)
    elif args.test_type == "icmp":
        if not validate_ip(args.target_host):
            logger.error("Invalid IP address format.")
            return
        send_icmp_echo(args.target_host, args.num_requests)
    elif args.test_type == "syn":
        if not validate_ip(args.target_host):
            logger.error("Invalid IP address format.")
            return
        send_tcp_syn(args.target_host, args.target_port, args.num_requests)


if __name__ == "__main__":
    asyncio.run(main())
