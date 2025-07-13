from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

@dataclass
class VulnerabilityFinding:
    file: Path
    start_line: int
    end_line: int
    danger_api: str
    function_name: Optional[str]
    code: str
    description: str = ""
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)

@dataclass
class VulnerabilityReport:
    findings: List[VulnerabilityFinding]
    summary: Optional[str] = ""
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict) 