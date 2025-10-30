"""Core scanning logic for the web application security scanner."""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Dict
from urllib.parse import parse_qsl, urlencode, urlparse

from .compat import BeautifulSoup, requests, urllib3

from .profiles import ScanProfile
from .reporting import Finding, ScanReport

SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "SQLite",
    "psql:",
    "You have an error in your SQL syntax",
    "warning: pg_query",
]

DIRECTORY_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

XSS_PAYLOAD = "<script>alert('xss')</script>"
SQLI_PAYLOAD = "' OR '1'='1"


@dataclass
class ScannerContext:
    session: requests.Session
    profile: ScanProfile
    request_kwargs: Dict[str, object]


class WebAppScanner:
    """High-level security scanner for web applications."""

    def __init__(self, base_url: str, profile: ScanProfile):
        if not base_url.lower().startswith(("http://", "https://")):
            raise ValueError("base_url must include the scheme (http or https)")
        self.base_url = base_url.rstrip("/")
        self.profile = profile
        self.session = requests.Session()
        self.http = urllib3.PoolManager()
        self.request_kwargs: Dict[str, object] = dict(profile.request_kwargs)
        if "headers" in self.request_kwargs:
            self.session.headers.update(self.request_kwargs.pop("headers"))
        self.session.headers.setdefault(
            "User-Agent",
            "WebAppScanner/1.0 (+https://example.com/security-scanner)",
        )

    def scan(self) -> ScanReport:
        """Execute all enabled checks and return a :class:`ScanReport`."""

        report = ScanReport(
            target_url=self.base_url,
            profile=self.profile.name,
            started_at=datetime.utcnow(),
        )
        context = ScannerContext(
            session=self.session, profile=self.profile, request_kwargs=self.request_kwargs
        )

        for check_name in self.profile.enabled_checks():
            handler = getattr(self, f"check_{check_name}", None)
            if not handler:
                continue
            try:
                handler(context, report)
            except requests.RequestException as exc:
                report.add_finding(
                    Finding(
                        title=f"{check_name.replace('_', ' ').title()} Scan Error",
                        severity="Info",
                        description="The scanner encountered an error while running this check.",
                        remediation="Review network connectivity and target availability.",
                        evidence=str(exc),
                    )
                )
        return report

    # Check implementations -------------------------------------------------

    def check_sql_injection(self, context: ScannerContext, report: ScanReport) -> None:
        """Test query parameters for SQL injection using boolean toggling."""

        original_response = self._get(context, self.base_url)
        if not original_response.ok:
            return

        parsed = urlparse(self.base_url)
        params = dict(parse_qsl(parsed.query)) or {"q": "test"}

        injected_params = {key: SQLI_PAYLOAD for key in params}
        injected_url = self._rebuild_url(parsed, injected_params)
        response = self._get(context, injected_url)

        evidence = None
        for error in SQL_ERRORS:
            if error.lower() in response.text.lower():
                evidence = error
                break

        if evidence or response.status_code >= 500:
            report.add_finding(
                Finding(
                    title="Possible SQL Injection",
                    severity="High",
                    description="The application responded with database error patterns when provided SQL injection payloads.",
                    remediation="Implement parameterised queries and input validation. Review database error handling to avoid leaking details.",
                    evidence=evidence or f"HTTP {response.status_code} returned",
                    references=["OWASP: https://owasp.org/www-community/attacks/SQL_Injection"],
                )
            )

    def check_xss(self, context: ScannerContext, report: ScanReport) -> None:
        """Attempt reflected XSS by injecting script payloads into parameters."""

        parsed = urlparse(self.base_url)
        params = dict(parse_qsl(parsed.query)) or {"q": "test"}
        payload_params = {key: XSS_PAYLOAD for key in params}
        target_url = self._rebuild_url(parsed, payload_params)

        response = self._get(context, target_url)
        if XSS_PAYLOAD.lower() in response.text.lower():
            report.add_finding(
                Finding(
                    title="Reflected XSS Detected",
                    severity="High",
                    description="The injected script payload was reflected unencoded in the response, indicating a potential XSS vulnerability.",
                    remediation="Sanitise user-supplied input before rendering. Leverage templating safeguards and Content Security Policy.",
                    evidence=f"Payload reflected at {target_url}",
                    references=["OWASP: https://owasp.org/www-community/attacks/xss/"],
                )
            )

    def check_csrf(self, context: ScannerContext, report: ScanReport) -> None:
        """Inspect forms for anti-CSRF token usage."""

        response = self._get(context, self.base_url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input", {"type": "hidden"})
            has_token = any(
                re.search(r"csrf|token|authenticity", (inp.get("name") or ""), re.I)
                for inp in inputs
            )
            if not has_token:
                action = form.get("action") or "same page"
                report.add_finding(
                    Finding(
                        title="Potential CSRF Vulnerability",
                        severity="Medium",
                        description="A form was found without an apparent anti-CSRF token.",
                        remediation="Include synchroniser tokens or double-submit cookies to protect against CSRF attacks.",
                        evidence=f"Form action: {action}",
                        references=["OWASP: https://owasp.org/www-community/attacks/csrf"],
                    )
                )

    def check_security_headers(self, context: ScannerContext, report: ScanReport) -> None:
        """Evaluate security-relevant HTTP response headers."""

        response = context.session.get(self.base_url)
        expected_headers = {
            "Content-Security-Policy": "Define a CSP to restrict sources.",
            "Strict-Transport-Security": "Enforce HTTPS via HSTS.",
            "X-Content-Type-Options": "Prevent MIME sniffing by setting nosniff.",
            "X-Frame-Options": "Mitigate clickjacking attacks.",
            "Referrer-Policy": "Limit sensitive referrer data leakage.",
        }

        for header, remediation in expected_headers.items():
            if header not in response.headers:
                report.add_finding(
                    Finding(
                        title=f"Missing Security Header: {header}",
                        severity="Medium",
                        description=f"The response from {self.base_url} did not include the {header} header.",
                        remediation=remediation,
                        references=["Mozilla Security Guidelines: https://infosec.mozilla.org/guidelines/web_security"],
                    )
                )

    def check_ssl(self, context: ScannerContext, report: ScanReport) -> None:
        """Inspect TLS configuration using urllib3 and ssl modules."""

        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            report.add_finding(
                Finding(
                    title="Insecure Scheme",
                    severity="High",
                    description="The target is served over HTTP without TLS.",
                    remediation="Serve the application exclusively over HTTPS with valid certificates.",
                )
            )
            return

        hostname = parsed.hostname
        port = parsed.port or 443

        context_ssl = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
        except (socket.error, ssl.SSLError) as exc:
            report.add_finding(
                Finding(
                    title="TLS Connection Failed",
                    severity="High",
                    description="The scanner could not complete a TLS handshake with the target.",
                    remediation="Verify TLS certificate validity and supported cipher suites.",
                    evidence=str(exc),
                )
            )
            return

        try:
            http_response = self.http.request(
                "GET", self.base_url, timeout=urllib3.Timeout(5.0), retries=False
            )
            report.metadata["https_status"] = str(http_response.status)
        except urllib3.exceptions.HTTPError as exc:
            report.add_finding(
                Finding(
                    title="HTTPS Request Failed",
                    severity="Medium",
                    description="The scanner could not perform an HTTPS request via urllib3.",
                    remediation="Check that the TLS certificate chain is valid and intermediates are served correctly.",
                    evidence=str(exc),
                )
            )

        if cert:
            not_after = cert.get("notAfter")
            if not_after:
                report.metadata["certificate_expires"] = not_after

        report.metadata["tls_version"] = tls_version or "unknown"
        report.metadata["cipher"] = ", ".join(map(str, cipher)) if cipher else "unknown"

        if tls_version in {"TLSv1", "TLSv1.1"}:
            report.add_finding(
                Finding(
                    title="Legacy TLS Version",
                    severity="Medium",
                    description=f"The server negotiated {tls_version}, which is considered weak.",
                    remediation="Disable legacy TLS versions and prefer TLS 1.2 or newer.",
                )
            )

    def check_directory_traversal(self, context: ScannerContext, report: ScanReport) -> None:
        """Attempt to access sensitive files via path traversal payloads."""

        parsed = urlparse(self.base_url)
        params = dict(parse_qsl(parsed.query)) or {"file": "test"}

        for payload in DIRECTORY_TRAVERSAL_PAYLOADS:
            payload_params = {key: payload for key in params}
            target_url = self._rebuild_url(parsed, payload_params)
            response = self._get(context, target_url)
            if "root:x" in response.text or "[extensions]" in response.text:
                report.add_finding(
                    Finding(
                        title="Directory Traversal Suspected",
                        severity="High",
                        description="Traversal payloads exposed sensitive file contents.",
                        remediation="Validate and normalise user-supplied file paths before use.",
                        evidence=f"Payload {payload} returned sensitive markers.",
                        references=["OWASP: https://owasp.org/www-community/attacks/Path_Traversal"],
                    )
                )
                break

    # Helper methods -------------------------------------------------------

    def _rebuild_url(self, parsed, params: Dict[str, str]) -> str:
        query = urlencode(params)
        return parsed._replace(query=query).geturl() if hasattr(parsed, "_replace") else self.base_url

    def _get(self, context: ScannerContext, url: str) -> requests.Response:
        return context.session.get(url, **context.request_kwargs)
