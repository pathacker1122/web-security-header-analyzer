# Web Security Header Analyzer

A lightweight Python command-line tool that inspects HTTP response headers on HTTPS websites.

## Installation

Clone this repository:

```bash
git clone https://github.com/pathacker1122/web-security-header-analyzer.git
cd web-security-header-analyzer
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Usage

Analyze an authorized HTTPS target:

```bash
python3 analyzer.py https://example.com
```

Save the results as JSON:

```bash
python3 analyzer.py https://example.com --json report.json
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Responsible Use

Use this tool only on websites you own or have permission to assess. Missing headers are findings to investigate, not proof of a vulnerability.
