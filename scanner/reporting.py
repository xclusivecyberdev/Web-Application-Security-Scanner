"""Reporting utilities for the web application security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional


@dataclass
class Finding:
    """Represents a single vulnerability finding."""

    title: str
    severity: str
    description: str
    remediation: str
    evidence: str | None = None
    references: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, str]:
        data = {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
        }
        if self.evidence:
            data["evidence"] = self.evidence
        if self.references:
            data["references"] = ", ".join(self.references)
        return data


@dataclass
class ScanReport:
    """Structured report containing scanner findings and metadata."""

    target_url: str
    profile: str
    started_at: datetime
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def is_clean(self) -> bool:
        return not self.findings

    def to_markdown(self) -> str:
        """Render the report in Markdown format."""

        lines = [
            f"# Web Application Security Scan Report",
            "",
            f"**Target:** {self.target_url}",
            f"**Profile:** {self.profile}",
            f"**Started:** {self.started_at.isoformat()}",
            f"**Total Findings:** {len(self.findings)}",
            "",
        ]

        if self.metadata:
            lines.append("## Metadata")
            for key, value in sorted(self.metadata.items()):
                lines.append(f"- **{key}:** {value}")
            lines.append("")

        if self.findings:
            lines.append("## Findings")
            for finding in self.findings:
                lines.extend(
                    [
                        f"### {finding.title}",
                        f"- **Severity:** {finding.severity}",
                        f"- **Description:** {finding.description}",
                        f"- **Remediation:** {finding.remediation}",
                    ]
                )
                if finding.evidence:
                    lines.append(f"- **Evidence:** {finding.evidence}")
                if finding.references:
                    lines.append(
                        "- **References:** " + ", ".join(finding.references)
                    )
                lines.append("")
        else:
            lines.append("No vulnerabilities were identified in the scanned scope.")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation of the report."""

        return {
            "target_url": self.target_url,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "findings": [finding.as_dict() for finding in self.findings],
            "metadata": self.metadata,
        }
