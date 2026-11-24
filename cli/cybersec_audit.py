#!/usr/bin/env python3
"""
CyberSec Toolkit CLI — HTTP Security Headers & TLS Certificate Auditor
Author: Hasib Hossain (@hasibcybersec)
"""

import argparse
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    requests = None

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _Ansi:
        CYAN = "\033[96m"
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        WHITE = "\033[97m"
        DIM = "\033[2m"
        RESET_ALL = "\033[0m"
    Fore = _Ansi()
    Style = _Ansi()

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protects against protocol downgrade and cookie hijacking (HSTS).",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks (CSP).",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding.",
    "X-Content-Type-Options": "Stops MIME-sniffing vulnerabilities (nosniff).",
    "Referrer-Policy": "Controls referrer header leakage to third-party origins.",
    "Permissions-Policy": "Restricts browser APIs (camera, geolocation, mic).",
}


def check_tls_expiry(hostname: str, port: int = 443) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            color = Fore.GREEN if days > 30 else Fore.YELLOW
            print(f"{color}[TLS] Certificate expires in {days} days ({exp.date()}){Style.RESET_ALL}")
    except Exception as exc:
        print(f"{Fore.RED}[TLS] Could not inspect TLS certificate: {exc}{Style.RESET_ALL}")


def fetch_headers(target: str):
    if requests is not None:
        resp = requests.get(target, timeout=10, allow_redirects=True)
        return resp.url, resp.status_code, resp.headers
    req = urllib.request.Request(target, headers={"User-Agent": "CyberSec-Toolkit/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.geturl(), resp.status, dict(resp.headers.items())


def audit_headers(url: str) -> int:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    target = parsed.geturl()
    print(f"{Fore.CYAN}\n[*] Auditing HTTP Security Headers: {target}{Style.RESET_ALL}")

    try:
        final_url, status, headers = fetch_headers(target)
    except Exception as exc:
        print(f"{Fore.RED}[!] Connection error: {exc}{Style.RESET_ALL}")
        return 1

    print(f"{Fore.WHITE}    Final URL: {final_url} (HTTP {status}){Style.RESET_ALL}\n")
    if parsed.scheme == "https" and parsed.hostname:
        check_tls_expiry(parsed.hostname)
        print()

    norm_headers = {k.lower(): v for k, v in headers.items()}
    score = 0
    for header, purpose in SECURITY_HEADERS.items():
        val = norm_headers.get(header.lower())
        if val:
            score += 1
            print(f"{Fore.GREEN}[PASS] {header}: {Style.RESET_ALL}{val}")
        else:
            print(f"{Fore.RED}[MISS] {header} {Style.DIM}— {purpose}{Style.RESET_ALL}")

    server_hdr = norm_headers.get("server")
    powered_by = norm_headers.get("x-powered-by")
    if server_hdr or powered_by:
        print(f"\n{Fore.YELLOW}[INFO] Fingerprint headers exposed: Server={server_hdr or 'none'}, X-Powered-By={powered_by or 'none'}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}[*] Security Header Score: {score}/{len(SECURITY_HEADERS)}{Style.RESET_ALL}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberSec Toolkit — HTTP Security Header & TLS Auditor")
    parser.add_argument("target", help="Target domain or URL (e.g. https://github.com)")
    args = parser.parse_args()
    return audit_headers(args.target)


if __name__ == "__main__":
    sys.exit(main())
