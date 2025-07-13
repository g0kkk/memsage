"""Post-processing module for vulnerability findings."""

from typing import List, Dict, Any
from dataclasses import dataclass
from .report import VulnerabilityFinding, Severity


@dataclass
class PostProcessingConfig:
    min_severity: Severity = Severity.LOW
    max_findings_per_file: int = 10
    deduplicate: bool = True


class PostProcessor:
    """Post-processes vulnerability findings."""
    
    def __init__(self, config: PostProcessingConfig = None):
        self.config = config or PostProcessingConfig()
    
    def process(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Process findings with filtering and deduplication."""
        processed = findings.copy()
        
        if self.config.deduplicate:
            processed = self._deduplicate(processed)
        
        processed = self._filter_by_severity(processed)
        processed = self._limit_per_file(processed)
        
        return processed
    
    def _deduplicate(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Remove duplicate findings and merge those with same file, line, and ruleId."""
        # Group findings by (file_path, line_number, rule_id)
        grouped = {}
        
        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        # Merge findings in each group
        merged = []
        for key, group in grouped.items():
            if len(group) == 1:
                # Single finding, no merging needed
                merged.append(group[0])
            else:
                # Multiple findings, merge them
                merged_finding = self._merge_findings(group)
                merged.append(merged_finding)
        
        return merged
    
    def _merge_findings(self, findings: List[VulnerabilityFinding]) -> VulnerabilityFinding:
        """Merge multiple findings into a single finding."""
        if not findings:
            raise ValueError("Cannot merge empty list of findings")
        
        # Use the first finding as base
        base = findings[0]
        
        # Take the highest severity using severity order
        severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
        highest_severity = max(findings, key=lambda f: severity_order[f.severity]).severity
        
        # Combine descriptions
        descriptions = [f.description for f in findings if f.description]
        combined_description = " | ".join(descriptions) if len(descriptions) > 1 else descriptions[0]
        
        # Combine taint paths (remove duplicates)
        all_taint_paths = []
        for finding in findings:
            if finding.taint_path:
                all_taint_paths.extend(finding.taint_path)
        unique_taint_paths = list(dict.fromkeys(all_taint_paths))  # Preserve order while removing duplicates
        
        return VulnerabilityFinding(
            file_path=base.file_path,
            line_number=base.line_number,
            severity=highest_severity,
            description=combined_description,
            rule_id=base.rule_id,
            function_name=base.function_name,
            taint_path=unique_taint_paths if unique_taint_paths else None
        )
    
    def _filter_by_severity(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Filter findings by minimum severity."""
        severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
        min_level = severity_order[self.config.min_severity]
        
        return [
            f for f in findings 
            if severity_order[f.severity] >= min_level
        ]
    
    def _limit_per_file(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Limit findings per file."""
        file_counts = {}
        limited = []
        
        for finding in findings:
            file_path = finding.file_path
            if file_counts.get(file_path, 0) < self.config.max_findings_per_file:
                file_counts[file_path] = file_counts.get(file_path, 0) + 1
                limited.append(finding)
        
        return limited 