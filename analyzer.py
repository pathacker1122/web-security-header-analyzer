
#!/usr/bin/env python3

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit


SECURITY_HEADERS = {
    "content-security-policy": (
        "Helps restrict which sources a browser can load content from."
    ),
    "strict-transport-security": (
        "Tells browsers to use HTTPS for future connections."
    ),
    "x-content-type-options": (
        "Helps prevent browsers from guessing content types."
    ),
    "referrer-policy": (
        "Controls how much referrer information browsers send."
    ),
    "permissions-policy": (
        "Controls access to selected browser features."
    ),
}


def validate_url(url):
    """Validate that the supplied URL is a valid HTTPS URL."""
    try:
        parsed = urlsplit(url)

        return (
            parsed.scheme.lower() == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
        )
    except (ValueError, AttributeError):
        return False


def analyze_headers(headers):
    """Identify security headers that are present or missing."""
    normalized = {
        name.lower(): value
        for name, value in headers.items()
    }

    results = {}

    for name, explanation in SECURITY_HEADERS.items():
        results[name] = {
            "present": name in normalized,
            "value": normalized.get(name),
            "explanation": explanation,
        }

    return results


def fetch_headers(url):
    """Fetch response headers while keeping TLS verification enabled."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "WebSecurityHeaderAnalyzer/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return (
                response.status,
                dict(response.headers.items()),
                response.geturl(),
            )

    except urllib.error.HTTPError as error:
        # HTTP error responses can still contain useful headers.
        return (
            error.code,
            dict(error.headers.items()),
            error.geturl(),
        )


def build_report(requested_url, final_url, status, headers):
    """Build a structured report from the HTTP response."""
    results = analyze_headers(headers)

    missing = [
        name
        for name, item in results.items()
        if not item["present"]
    ]

    return {
        "requested_url": requested_url,
        "final_url": final_url,
        "http_status": status,
        "summary": {
            "total_checked": len(results),
            "present": len(results) - len(missing),
            "missing": len(missing),
        },
        "headers": results,
        "note": (
            "Header presence alone does not establish whether "
            "a security configuration is effective. Review each "
            "header's value and the application's requirements."
        ),
    }


def print_report(report):
    """Display a readable summary in the terminal."""
    print(f"\nURL: {report['final_url']}")
    print(f"HTTP status: {report['http_status']}")
    print("\nSecurity Header Results")
    print("-" * 50)

    for name, item in report["headers"].items():
        state = "PRESENT" if item["present"] else "MISSING"
        print(f"{state:7} {name}")

    summary = report["summary"]

    print("\nSummary")
    print(f"Headers checked: {summary['total_checked']}")
    print(f"Present: {summary['present']}")
    print(f"Missing: {summary['missing']}")

    missing = [
        name
        for name, item in report["headers"].items()
        if not item["present"]
    ]

    if missing:
        print("\nHeaders to review:")
        for name in missing:
            print(f"- {name}")

    print("\nNote: Missing headers are findings to review,")
    print("not proof on their own that a website is vulnerable.")


def save_json_report(report, output_path):
    """Save the report as formatted JSON."""
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze HTTP security headers on an HTTPS URL."
    )

    parser.add_argument(
        "url",
        help="HTTPS URL to analyze",
    )

    parser.add_argument(
        "--json",
        dest="output",
        help="Save the results to a JSON file",
    )

    args = parser.parse_args()

    if not validate_url(args.url):
        parser.error(
            "Invalid URL. Provide a valid HTTPS URL, "
            "such as https://example.com"
        )

    try:
        status, headers, final_url = fetch_headers(args.url)

    except urllib.error.URLError as error:
        reason = getattr(error, "reason", error)

        if "CERTIFICATE_VERIFY_FAILED" in str(reason):
            print(
                "TLS certificate verification failed. Check the "
                "server certificate and your system CA certificates. "
                "Certificate verification remains enabled.",
                file=sys.stderr,
            )
        else:
            print(f"Request failed: {reason}", file=sys.stderr)

        return 1

    except (TimeoutError, OSError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 1

    report = build_report(
        requested_url=args.url,
        final_url=final_url,
        status=status,
        headers=headers,
    )

    print_report(report)

    if args.output:
        try:
            save_json_report(report, args.output)
            print(f"\nJSON report saved to {args.output}")

        except OSError as error:
            print(
                f"Could not save JSON report: {error}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
