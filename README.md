# Web Application Security Scanner

A lightweight Python-based web application vulnerability scanner that focuses on fast reconnaissance for common issues such as SQL injection, cross-site scripting, CSRF, weak security headers, SSL/TLS configuration problems, and directory traversal flaws. The scanner is designed strictly for educational use and for defensive security teams performing authorised testing engagements. You are solely responsible for how you use this tool.

## Features

- **SQL Injection detection** – submits boolean-based payloads and looks for database error signatures.
- **Reflected XSS detection** – injects JavaScript payloads into parameters and observes reflections.
- **CSRF analysis** – inspects HTML forms for anti-CSRF tokens.
- **Security headers audit** – validates presence of high-impact HTTP headers.
- **SSL/TLS checks** – inspects negotiated TLS version, cipher suite, certificate expiry, and request success via `urllib3`.
- **Directory traversal detection** – attempts to fetch sensitive files with traversal payloads.
- **Custom scan profiles** – toggle checks and request options via predefined or JSON-based profiles.
- **Detailed reporting** – export findings in Markdown or JSON with remediation guidance.

## Installation

The scanner requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # see optional step below
```

A `requirements.txt` file is not provided by default. Install the runtime dependencies manually:

```bash
pip install requests beautifulsoup4 urllib3
```

If the optional dependencies above are not available, the scanner falls back to a minimal built-in HTTP client and HTML parser so that the CLI can still run in constrained environments. The bundled fallbacks provide only the features required by the scanner and are not a substitute for the full third-party packages in production use.

## Usage

Run the scanner via the module entry point:

```bash
python -m scanner <target-url> [--profile PROFILE] [--output FILE] [--format {markdown,json}]
```

Examples:

```bash
# Basic scan with Markdown report printed to stdout
python -m scanner https://example.com

# Full scan with JSON report saved to disk
python -m scanner https://example.com --profile full --output report.json

# Custom profile from a JSON file
python -m scanner https://example.com --profile profiles/custom.json
```

The scanner exits with status code `0` when no findings are detected and `1` otherwise. Reports include remediation suggestions and reference links for each finding.

### Profiles

Profiles enable tuning the enabled checks and HTTP client behaviour. Two presets are bundled:

- `basic` – high-impact checks with a shorter timeout.
- `full` – enables all checks and increases network timeouts.

A custom profile can be created using JSON:

```json
{
  "name": "staging",
  "description": "Full scan with relaxed timeouts for staging environments",
  "checks": {
    "sql_injection": true,
    "xss": true,
    "csrf": true,
    "security_headers": true,
    "ssl": true,
    "directory_traversal": true
  },
  "request_kwargs": {
    "timeout": 30,
    "verify": false
  }
}
```

Pass the JSON file path to `--profile` to load it.

## Reporting

By default the CLI prints a Markdown report. Use `--format json` or a `.json` output filename to receive JSON instead. Reports include:

- Scan metadata (target, profile name, timestamps, TLS details)
- Each finding with severity, description, remediation, evidence, and references

The JSON output can be ingested into ticketing systems or dashboards for further processing.

## Ethical Hacking Guidelines

This project is provided for defensive and educational use. When operating the scanner:

1. **Obtain written authorisation** – only test systems where you have explicit permission.
2. **Respect scope and rate limits** – remain within the agreed target range and avoid actions that could disrupt availability.
3. **Protect data** – securely store or delete any sensitive information retrieved during testing.
4. **Disclose responsibly** – share results with the system owner and allow reasonable time for remediation before public disclosure.
5. **Follow local laws and regulations** – ensure compliance with all applicable legal requirements.

## Legal Disclaimer

- This tool is intended for authorised security testing and educational experimentation only. Using it against systems without permission may violate laws and regulations and could lead to civil penalties, criminal charges, or imprisonment.
- You accept full responsibility for any actions performed with this software. Misuse can result in severe legal consequences, including jail or prison sentences.
- The author and contributors of this project are not liable for any damages or legal outcomes arising from the use or misuse of the scanner.

## Limitations

- The scanner performs heuristic checks and may produce false positives or negatives.
- Only reflected XSS is tested; stored and DOM-based variants are not covered.
- SQL injection detection is limited to basic error-based techniques.
- TLS analysis is limited to the negotiated version and handshake success.

Always complement automated scanning with manual verification and deeper analysis.
