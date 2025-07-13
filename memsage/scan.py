"""Enhanced repository scanning with LLM-powered vulnerability detection."""

from pathlib import Path
from typing import Union, Optional
import time
from .parser import walk_cpp_files
from .slicer import SliceExtractor
from .report import VulnerabilityFinding, VulnerabilityReport, Severity
from .llm import LLMAnalyzer, LLMProvider
from .config import ScanConfig, ConfigManager
from .postproc import PostProcessor, PostProcessingConfig
import json

def scan_repository(path: Union[str, Path], config: Optional[ScanConfig] = None) -> VulnerabilityReport:
    """
    Scan a C++ repository for memory safety vulnerabilities using LLM-powered analysis.
    
    Args:
        path: Path to the root of the repository
        config: Optional configuration for scanning
        
    Returns:
        VulnerabilityReport with all findings
    """
    start_time = time.time()
    root = Path(path)
    
    # Load configuration
    if config is None:
        config_manager = ConfigManager()
        config = config_manager.get_config()
    
    print(f"Scanning repository: {root}")
    print(f"LLM Provider: {config.llm_provider}")
    print(f"LLM Model: {config.llm_model}")
    print(f"Parallel Workers: {config.parallel_workers}")
    print(f"Max Cost: ${config.max_cost}")
    
    # Find C++ files
    files = list(walk_cpp_files(root))
    print(f"Found {len(files)} C++ files to analyze")
    
    if not files:
        return VulnerabilityReport(
            findings=[],
            total_files_scanned=0,
            scan_duration=time.time() - start_time,
            summary="No C++ files found"
        )
    
    # Initialize components
    extractor = SliceExtractor(debug=config.debug, context_lines=config.context_lines)
    # Determine version_source for AnthropicClient
    version_source = "default"
    import os
    import sys
    # Check if set via CLI (sys.argv)
    if any(arg.startswith("--anthropic-version") for arg in sys.argv):
        version_source = "cli"
    elif os.getenv("ANTHROPIC_VERSION"):
        version_source = "env"
    llm_analyzer = LLMAnalyzer(
        provider=LLMProvider(config.llm_provider),
        model=config.llm_model,
        parallel_workers=config.parallel_workers,
        anthropic_version=config.anthropic_version,
        version_source=version_source
    )
    
    # Extract slices from all files
    all_slices = []
    for file_path in files:
        try:
            slices = extractor.extract_slices(file_path)
            all_slices.extend(slices)
        except Exception as e:
            print(f"Error extracting slices from {file_path}: {e}")
    
    print(f"Extracted {len(all_slices)} code slices")
    
    # Filter slices by minimum line count
    filtered_slices = []
    skipped_count = 0
    for slice in all_slices:
        line_count = slice.end_line - slice.start_line + 1
        if line_count >= config.min_lines:
            filtered_slices.append(slice)
        else:
            skipped_count += 1
    
    if skipped_count > 0:
        print(f"Filtered out {skipped_count} slices shorter than {config.min_lines} lines")
    
    all_slices = filtered_slices
    print(f"Analyzing {len(all_slices)} slices (min {config.min_lines} lines)")
    
    # Filter slices by maximum line count
    if config.max_lines:
        max_filtered_slices = []
        max_skipped_count = 0
        for slice in all_slices:
            line_count = slice.end_line - slice.start_line + 1
            if line_count <= config.max_lines:
                max_filtered_slices.append(slice)
            else:
                max_skipped_count += 1
        
        if max_skipped_count > 0:
            print(f"Filtered out {max_skipped_count} slices longer than {config.max_lines} lines")
        
        all_slices = max_filtered_slices
        print(f"Analyzing {len(all_slices)} slices (max {config.max_lines} lines)")
    
    # Filter slices by required evidence patterns
    if config.require_evidence:
        import re
        evidence_filtered_slices = []
        evidence_skipped_count = 0
        
        for slice in all_slices:
            slice_text = slice.code.lower()  # Case-insensitive matching
            all_patterns_match = True
            
            for pattern in config.require_evidence:
                if not re.search(pattern, slice_text, re.IGNORECASE):
                    all_patterns_match = False
                    break
            
            if all_patterns_match:
                evidence_filtered_slices.append(slice)
            else:
                evidence_skipped_count += 1
        
        if evidence_skipped_count > 0:
            print(f"Filtered out {evidence_skipped_count} slices missing required evidence patterns: {', '.join(config.require_evidence)}")
        
        all_slices = evidence_filtered_slices
        print(f"Analyzing {len(all_slices)} slices with required evidence")
    
    if not all_slices:
        return VulnerabilityReport(
            findings=[],
            total_files_scanned=len(files),
            scan_duration=time.time() - start_time,
            summary="No vulnerable code patterns found"
        )
    
    # Estimate cost
    estimated_cost = llm_analyzer.get_cost_estimate([
        {"code": s.code, "context": s.context} for s in all_slices
    ])
    
    print(f"Estimated LLM cost: ${estimated_cost:.4f}")
    
    if estimated_cost > config.max_cost:
        print(f"Warning: Estimated cost (${estimated_cost:.4f}) exceeds limit (${config.max_cost})")
        if not config.force_scan:
            print("Aborting scan. Use --force to override.")
            return VulnerabilityReport(
                findings=[],
                total_files_scanned=len(files),
                scan_duration=time.time() - start_time,
                summary=f"Scan aborted due to cost limit (${estimated_cost:.4f} > ${config.max_cost})"
            )
    
    # Convert slices to dict format for LLM analyzer
    slice_data = []
    for slice in all_slices:
        slice_data.append({
            "file_path": slice.file_path,
            "start_line": slice.start_line,
            "end_line": slice.end_line,
            "code": slice.code,
            "context": slice.context,
            "danger_api": slice.danger_api,
            "function_name": slice.function_name,
            "severity": slice.severity.value,
            "pattern_matched": slice.pattern_matched
        })
    
    # Analyze slices with LLM (now with live progress tracking)
    print("Analyzing code slices with LLM...")
    llm_results = llm_analyzer.analyze_slices(slice_data)
    
    # Convert LLM results to VulnerabilityFinding objects
    findings = []
    for result in llm_results:
        analysis = result.get("analysis", {})
        
        # Map severity string to enum
        severity_str = analysis.get("severity", "medium").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)
        
        # Determine rule ID based on vulnerability type or danger API
        rule_id = _determine_rule_id(analysis, result)
        
        finding = VulnerabilityFinding(
            file_path=result["file_path"],
            line_number=result["start_line"],
            severity=severity,
            description=analysis.get("description", "Vulnerability detected"),
            rule_id=rule_id,
            function_name=result.get("function_name", "unknown"),
            taint_path=None  # Could be enhanced with taint analysis
        )
        findings.append(finding)
    
    # Filter findings by only_rules if specified
    if config.only_rules:
        rule_filtered_findings = []
        rule_skipped_count = 0
        
        for finding in findings:
            if finding.rule_id in config.only_rules:
                rule_filtered_findings.append(finding)
            else:
                rule_skipped_count += 1
        
        if rule_skipped_count > 0:
            print(f"Filtered out {rule_skipped_count} findings not matching specified rules: {', '.join(config.only_rules)}")
        
        findings = rule_filtered_findings
        print(f"Analyzing {len(findings)} findings matching specified rules")
    
    # Filter findings by rule-specific severity thresholds
    if config.min_severity_per_rule:
        rule_filtered_findings = []
        rule_filtered_count = 0
        
        for finding in findings:
            rule_id = finding.rule_id
            if rule_id in config.min_severity_per_rule:
                # Get the minimum severity for this rule
                min_severity_str = config.min_severity_per_rule[rule_id].lower()
                min_severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW
                }
                min_severity = min_severity_map.get(min_severity_str, Severity.LOW)
                
                # Only keep findings that meet or exceed the rule-specific threshold
                if finding.severity.value >= min_severity.value:
                    rule_filtered_findings.append(finding)
                else:
                    rule_filtered_count += 1
            else:
                # No specific threshold for this rule, keep it
                rule_filtered_findings.append(finding)
        
        if rule_filtered_count > 0:
            print(f"Filtered out {rule_filtered_count} findings below rule-specific severity thresholds")
        
        findings = rule_filtered_findings
    
    # Post-process findings with deduplication
    post_config = PostProcessingConfig(
        min_severity=config.min_severity,
        max_findings_per_file=10,
        deduplicate=True
    )
    post_processor = PostProcessor(post_config)
    processed_findings = post_processor.process(findings)
    
    # Generate summary with deduplicated counts
    scan_duration = time.time() - start_time
    total_cost = llm_analyzer.get_total_cost()
    
    # Create report with processed findings
    report = VulnerabilityReport(
        findings=processed_findings,
        total_files_scanned=len(files),
        scan_duration=scan_duration
    )
    
    # Generate summary with deduplication info
    original_count = len(findings)
    deduplicated_count = len(processed_findings)
    duplicates_removed = original_count - deduplicated_count
    
    summary = f"""Scan completed in {scan_duration:.2f} seconds
Total files scanned: {len(files)}
Total slices analyzed: {len(all_slices)}
Total findings: {deduplicated_count} (deduplicated from {original_count})
Duplicates removed: {duplicates_removed}
LLM cost: ${total_cost:.4f}

Findings by severity:
- Critical: {report.critical_count}
- High: {report.high_count}
- Medium: {report.medium_count}
- Low: {report.low_count}"""
    
    report.summary = summary
    return report


def _determine_rule_id(analysis: dict, result: dict) -> str:
    """Determine rule ID based on vulnerability type or danger API."""
    # Try to get rule ID from LLM response first
    vuln_type = analysis.get("vulnerability_type", "").lower()
    
    # Map common vulnerability types to rule IDs
    vuln_type_map = {
        "buffer overflow": "buffer-overflow",
        "use after free": "use-after-free", 
        "use-after-free": "use-after-free",
        "double free": "double-free",
        "double-free": "double-free",
        "format string": "format-string",
        "format-string": "format-string",
        "integer overflow": "integer-overflow",
        "integer-overflow": "integer-overflow",
        "null pointer": "null-pointer-dereference",
        "null-pointer": "null-pointer-dereference",
        "memory leak": "memory-leak",
        "memory-leak": "memory-leak"
    }
    
    if vuln_type in vuln_type_map:
        return vuln_type_map[vuln_type]
    
    # Fallback: determine from danger API or description
    description = analysis.get("description", "").lower()
    
    if any(api in description for api in ["strcpy", "memcpy", "sprintf"]):
        return "buffer-overflow"
    elif any(api in description for api in ["delete", "free"]):
        return "use-after-free"
    elif "printf" in description and "format" in description:
        return "format-string"
    elif any(api in description for api in ["malloc", "new"]):
        return "memory-leak"
    else:
        return "unknown" 