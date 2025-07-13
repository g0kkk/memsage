"""Vulnerability reporting module."""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityFinding:
    file_path: str
    line_number: int
    severity: Severity
    description: str
    rule_id: str = "unknown"  # Added ruleId for deduplication
    function_name: str = "unknown"  # Added function_name for SARIF deduplication
    taint_path: Optional[List[str]] = None


@dataclass
class VulnerabilityReport:
    findings: List[VulnerabilityFinding]
    total_files_scanned: int = 0
    scan_duration: float = 0.0
    summary: str = ""
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
    
    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL])
    
    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH])
    
    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.MEDIUM])
    
    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.LOW])
    
    def get_severity_distribution(self) -> dict:
        """Get distribution of findings by severity."""
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count
        } 