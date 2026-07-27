#!/usr/bin/env python3
"""B2B Audit Header Scanner.

Checks HTTP security headers on URLs and generates a Markdown report.
"""

import argparse
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException, ConnectionError, Timeout


@dataclass
class HeaderCheck:
    """Result of a single header check."""
    header: str
    required: bool
    found: bool
    value: str = ""
    score: int = 0  # 0=missing, 1=partial, 2=good

    @property
    def status(self) -> str:
        if self.found:
            return "PASS" if self.score >= 2 else "WARN"
        return "FAIL" if self.required else "SKIP"

    @property
    def severity(self) -> str:
        if not self.found and self.required:
            return "HIGH"
        return "LOW"


@dataclass
class UrlResult:
    """Result for a single URL."""
    url: str
    status_code: int = 0
    response_time: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    checks: List[HeaderCheck] = field(default_factory=list)
    score: int = 0
    grade: str = ""


def get_default_checks() -> List[Dict[str, Any]]:
    """Standard set of security header checks."""
    return [
        {"header": "Strict-Transport-Security", "required": True, "min_len": 1},
        {"header": "Content-Security-Policy", "required": True, "min_len": 1},
        {"header": "X-Content-Type-Options", "required": True, "expected": "nosniff"},
        {"header": "X-Frame-Options", "required": True, "expected": "DENY"},
        {"header": "Cache-Control", "required": False, "min_len": 1},
        {"header": "Permissions-Policy", "required": True, "min_len": 1},
        {"header": "Referrer-Policy", "required": True, "min_len": 1},
        {"header": "Cross-Origin-Opener-Policy", "required": True, "min_len": 1},
        {"header": "Cross-Origin-Resource-Policy", "required": False, "min_len": 1},
        {"header": "Cross-Origin-Embedder-Policy", "required": False, "min_len": 1},
        {"header": "Public-Key-Pins", "required": False, "min_len": 1},
        {"header": "X-XSS-Protection", "required": False, "expected": "1; mode=block"},
    ]


def check_header(check_def: Dict[str, Any], headers: Dict[str, str]) -> HeaderCheck:
    """Evaluate a single header check against actual headers."""
    header_name = check_def["header"]
    # Case-insensitive header lookup
    actual = None
    for k, v in headers.items():
        if k.lower() == header_name.lower():
            actual = v
            break

    found = actual is not None
    score = 0
    value = actual or ""

    if found:
        if "expected" in check_def:
            expected = check_def["expected"]
            if actual.lower().startswith(expected.lower().split(";")[0].strip()):
                score = 2
            else:
                score = 1
        elif "min_len" in check_def:
            if len(actual) >= check_def["min_len"]:
                score = 2
            else:
                score = 1
        else:
            score = 2
        # HSTS needs max-age check
        if header_name == "Strict-Transport-Security" and "max-age" in actual.lower():
            try:
                max_age = int([p for p in actual.split(";") if "max-age" in p.lower()][0].split("=")[1].strip())
                if max_age >= 31536000:  # 1 year
                    score = 2
                else:
                    score = 1
            except (IndexError, ValueError):
                score = 1
    elif check_def["required"]:
        score = 0

    return HeaderCheck(
        header=header_name,
        required=check_def["required"],
        found=found,
        value=value,
        score=score,
    )


def scan_url(url: str, timeout: int = 10) -> UrlResult:
    """Scan a single URL for security headers."""
    result = UrlResult(url=url)
    checks = get_default_checks()

    try:
        start = time.time()
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        result.status_code = resp.status_code
        result.response_time = round(time.time() - start, 3)
        result.headers = dict(resp.headers)

        for check_def in checks:
            hc = check_header(check_def, resp.headers)
            result.checks.append(hc)

        # Calculate score
        total_points = sum(c.score for c in result.checks)
        max_points = len(result.checks) * 2
        result.score = round((total_points / max_points) * 100) if max_points > 0 else 0

        # Grade
        if result.score >= 90:
            result.grade = "A+"
        elif result.score >= 80:
            result.grade = "A"
        elif result.score >= 70:
            result.grade = "B"
        elif result.score >= 60:
            result.grade = "C"
        elif result.score >= 40:
            result.grade = "D"
        else:
            result.grade = "F"

    except (RequestException, ConnectionError, Timeout) as e:
        result.status_code = -1
        result.response_time = 0.0
        for check_def in checks:
            result.checks.append(HeaderCheck(
                header=check_def["header"],
                required=check_def["required"],
                found=False,
                score=0,
            ))
        result.score = 0
        result.grade = "ERR"

    return result


def generate_markdown_report(results: List[UrlResult]) -> str:
    """Generate a Markdown report from scan results."""
    lines = [
        "# B2B Security Header Audit Report",
        "",
        f"**URLs scanned:** {len(results)}",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "## Summary",
        "",
    ]

    grades = {}
    for r in results:
        g = r.grade
        grades[g] = grades.get(g, 0) + 1
    for g, count in sorted(grades.items()):
        lines.append(f"- {g}: {count} URL(s)")
    lines.append("")

    for result in results:
        lines.append(f"## {result.url}")
        lines.append("")
        lines.append(f"**Grade:** {result.grade} | **Score:** {result.score}/100")
        lines.append(f"**Status Code:** {result.status_code} | **Response Time:** {result.response_time}s")
        lines.append("")

        if result.checks:
            lines.append("### Header Checks")
            lines.append("")
            lines.append("| Header | Required | Status | Value |")
            lines.append("|--------|----------|--------|-------|")
            for check in result.checks:
                display_val = check.value[:60] + "..." if len(check.value) > 60 else check.value
                lines.append(f"| {check.header} | {'Yes' if check.required else 'No'} | {check.status} | {display_val} |")
            lines.append("")

        # Show findings
        fails = [c for c in result.checks if c.status == "FAIL"]
        warns = [c for c in result.checks if c.status == "WARN"]
        if fails:
            lines.append("### FAILURES")
            lines.append("")
            for f in fails:
                lines.append(f"- [HIGH] {f.header} is missing")
            lines.append("")
        if warns:
            lines.append("### WARNINGS")
            lines.append("")
            for w in warns:
                lines.append(f"- [LOW] {w.header}: {w.value[:80]}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="B2B Audit Header Scanner")
    parser.add_argument("urls", nargs="*", help="URLs to scan")
    parser.add_argument("-f", "--file", help="File with one URL per line")
    parser.add_argument("-o", "--output", default="report.md", help="Markdown report output path")
    parser.add_argument("--json", action="store_true", help="Output scan results as JSON")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")

    args = parser.parse_args()

    urls: List[str] = []
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        with open(args.file, "r") as f:
            urls.extend([line.strip() for line in f if line.strip()])

    if not urls:
        print("Error: provide URLs or a file with URLs", file=sys.stderr)
        sys.exit(1)

    results: List[UrlResult] = []
    for url in urls:
        print(f"Scanning: {url}")
        r = scan_url(url, timeout=args.timeout)
        results.append(r)

    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        report = generate_markdown_report(results)
        output_path = Path(args.output)
        output_path.write_text(report, encoding="utf-8")
        print(f"\nReport written to: {output_path}")
        print(f"{'='*60}")
        for r in results:
            print(f"  {r.url} -> {r.grade} ({r.score}/100)")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
