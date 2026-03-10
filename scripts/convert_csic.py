#!/usr/bin/env python3
"""
Convert CSIC 2010 HTTP dataset files into Sunbeam audit-log JSONL format.

The CSIC 2010 dataset contains raw HTTP/1.1 requests separated by blank lines.
Label is determined by which file it came from (normal vs anomalous).

Usage:
    # Download the dataset first:
    git clone https://src.sunbeam.pt/studio/csic-dataset.git /tmp/csic

    # Convert all three files:
    python3 scripts/convert_csic.py \
        --normal /tmp/csic/OriginalDataSets/normalTrafficTraining.txt \
        --normal /tmp/csic/OriginalDataSets/normalTrafficTest.txt \
        --anomalous /tmp/csic/OriginalDataSets/anomalousTrafficTest.txt \
        --hosts admin,src,docs,auth,drive,grafana,people,meet,s3,livekit \
        --output csic_converted.jsonl

    # Merge with production logs:
    cat logs.jsonl csic_converted.jsonl > combined.jsonl

    # Train (or just use --csic flag which does this automatically):
    cargo run -- train-scanner --input combined.jsonl --output scanner_model.bin
    # Simpler: cargo run -- train-scanner --input logs.jsonl --output scanner_model.bin --csic
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote


def parse_csic_file(filepath):
    """Parse a CSIC 2010 raw HTTP file into individual requests."""
    requests = []
    current_lines = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.rstrip("\r\n")
            if stripped == "" and current_lines:
                req = parse_single_request(current_lines)
                if req:
                    requests.append(req)
                current_lines = []
            else:
                current_lines.append(stripped)

    # Handle last request if file doesn't end with blank line
    if current_lines:
        req = parse_single_request(current_lines)
        if req:
            requests.append(req)

    return requests


def parse_single_request(lines):
    """Parse a single HTTP request from its lines into a dict of headers/fields."""
    if not lines:
        return None

    # First line: METHOD url HTTP/1.1
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        return None

    method = parts[0]
    raw_url = parts[1]

    # Extract path from URL (may be absolute like http://localhost:8080/path)
    parsed = urlparse(raw_url)
    path = parsed.path or "/"
    query = parsed.query or ""

    # Parse headers
    headers = {}
    body_start = None
    for i, line in enumerate(lines[1:], start=1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()

    # Extract body if present
    body = ""
    if body_start and body_start < len(lines):
        body = "\n".join(lines[body_start:])

    content_length = 0
    if "content-length" in headers:
        try:
            content_length = int(headers["content-length"])
        except ValueError:
            content_length = len(body)
    elif body:
        content_length = len(body)

    return {
        "method": method,
        "path": path,
        "query": query,
        "user_agent": headers.get("user-agent", "-"),
        "has_cookies": "cookie" in headers,
        "content_length": content_length,
        "referer": headers.get("referer", "-"),
        "accept_language": headers.get("accept-language", "-"),
        "accept": headers.get("accept", "*/*"),
        "host_header": headers.get("host", "localhost:8080"),
    }


def to_audit_jsonl(req, label, configured_hosts, base_time, offset_secs):
    """Convert a parsed request into our audit log JSONL format."""
    # Assign a host: normal traffic gets a configured host, attack gets random
    if label == "normal":
        host_prefix = random.choice(configured_hosts)
        status = random.choice([200, 200, 200, 200, 301, 304])
    else:
        # 70% unknown host, 30% configured (attacks do hit real hosts)
        if random.random() < 0.7:
            host_prefix = random.choice([
                "unknown", "scanner", "probe", "test",
                "random-" + str(random.randint(1000, 9999)),
            ])
        else:
            host_prefix = random.choice(configured_hosts)
        status = random.choice([404, 404, 404, 400, 403, 500])

    host = f"{host_prefix}.sunbeam.pt"

    # Synthesize a client IP
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    timestamp = (base_time + timedelta(seconds=offset_secs)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )

    referer = req["referer"]
    accept_language = req["accept_language"]

    # For anomalous samples, simulate realistic scanner behavior:
    # scanners don't carry session cookies, referer, or accept-language.
    # CSIC attacks all have these because they were generated from a user
    # session — strip them to match what real scanners look like.
    if label != "normal":
        has_cookies = False
        referer = "-"
        # 80% drop accept-language (most scanners), 20% keep (sophisticated ones)
        if random.random() < 0.8:
            accept_language = "-"
        # 40% use a scanner-like UA instead of the CSIC browser UA
        r = random.random()
        if r < 0.15:
            user_agent = ""
        elif r < 0.25:
            user_agent = "curl/7.68.0"
        elif r < 0.35:
            user_agent = "python-requests/2.28.0"
        elif r < 0.40:
            user_agent = f"Go-http-client/1.1"
        else:
            user_agent = req["user_agent"]
    else:
        has_cookies = req["has_cookies"]
        user_agent = req["user_agent"]

    entry = {
        "timestamp": timestamp,
        "level": "INFO",
        "fields": {
            "message": "request",
            "target": "audit",
            "method": req["method"],
            "host": host,
            "path": req["path"],
            "query": req.get("query", ""),
            "client_ip": ip,
            "status": status,
            "duration_ms": random.randint(1, 50),
            "content_length": req["content_length"],
            "user_agent": user_agent,
            "referer": referer,
            "accept_language": accept_language,
            "accept": req["accept"],
            "has_cookies": has_cookies,
            "cf_country": "-",
            "backend": f"{host_prefix}-svc:8080" if label == "normal" else "-",
            "label": "normal" if label == "normal" else "attack",
        },
        "target": "sunbeam_proxy::proxy",
    }

    return json.dumps(entry, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description="Convert CSIC 2010 dataset to Sunbeam audit-log JSONL"
    )
    parser.add_argument(
        "--normal",
        action="append",
        default=[],
        help="Path to normal traffic file(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--anomalous",
        action="append",
        default=[],
        help="Path to anomalous traffic file(s). Can be specified multiple times.",
    )
    parser.add_argument(
        "--hosts",
        default="admin,src,docs,auth,drive,grafana,people,meet,s3,livekit",
        help="Comma-separated list of configured host prefixes (default: sunbeam.pt subdomains)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        default=True,
        help="Shuffle output to interleave normal/attack (default: true)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    if not args.normal and not args.anomalous:
        parser.error("provide at least one --normal or --anomalous file")

    random.seed(args.seed)
    configured_hosts = [h.strip() for h in args.hosts.split(",")]
    base_time = datetime(2026, 3, 1, 0, 0, 0)

    # Parse all files
    labeled = []

    for path in args.normal:
        reqs = parse_csic_file(path)
        print(f"parsed {len(reqs)} normal requests from {path}", file=sys.stderr)
        for r in reqs:
            labeled.append((r, "normal"))

    for path in args.anomalous:
        reqs = parse_csic_file(path)
        print(f"parsed {len(reqs)} anomalous requests from {path}", file=sys.stderr)
        for r in reqs:
            labeled.append((r, "anomalous"))

    if args.shuffle:
        random.shuffle(labeled)

    print(
        f"total: {len(labeled)} requests "
        f"({sum(1 for _, l in labeled if l == 'normal')} normal, "
        f"{sum(1 for _, l in labeled if l == 'anomalous')} anomalous)",
        file=sys.stderr,
    )

    # Write output
    out = open(args.output, "w") if args.output != "-" else sys.stdout
    try:
        for i, (req, label) in enumerate(labeled):
            line = to_audit_jsonl(req, label, configured_hosts, base_time, i)
            out.write(line + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    if args.output != "-":
        print(f"written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
