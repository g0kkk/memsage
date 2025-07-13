"""Command-line interface for MemSage."""

import typer
from pathlib import Path
from .scan import scan_repository
from .config import ConfigManager, ScanConfig, OutputFormat
from .report import Severity
import sys
import multiprocessing

app = typer.Typer()

@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to C++ project or file to scan."),
    cost_dry_run: bool = typer.Option(False, "--cost-dry-run", help="Estimate Claude token spend and exit."),
    max_cost: float = typer.Option(50.0, "--max-cost", help="Maximum spending limit in USD."),
    format: str = typer.Option("console", "--format", help="Output format (console, sarif, json)."),
    output: str = typer.Option(None, "--output", help="Output file or directory."),
    provider: str = typer.Option("ollama", "--provider", help="LLM provider (ollama, anthropic)."),
    model: str = typer.Option(None, "--model", help="LLM model to use."),
    min_severity: str = typer.Option("low", "--min-severity", help="Minimum severity to report (low, medium, high, critical)."),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output."),
    force: bool = typer.Option(False, "--force", help="Force scan even if cost limit exceeded."),
    parallel_workers: int = typer.Option(
        None, "--parallel-workers", help="Number of concurrent LLM requests (default: min(8, cpu_count()))"
    ),
    anthropic_version: str = typer.Option(None, "--anthropic-version", help="Anthropic API version (default: 2023-06-01)."),
    min_lines: int = typer.Option(3, "--min-lines", help="Minimum lines for a code slice to be analyzed (default: 3)."),
    max_lines: int = typer.Option(None, "--max-lines", help="Maximum lines for a code slice to be analyzed (default: no limit)."),
    require_evidence: str = typer.Option(None, "--require-evidence", help="Comma-separated regex patterns that must match in slice (e.g., 'strcpy,memcpy')"),
    min_severity_per_rule: str = typer.Option(None, "--min-severity-per-rule", help="Rule-specific severity thresholds (e.g., 'buffer-overflow=high,format-string=medium')"),
    only_rules: str = typer.Option(None, "--only-rules", help="Comma-separated list of rules to check (e.g., 'buffer-overflow,use-after-free,format-string')"),
    context_lines: int = typer.Option(8, "--context-lines", help="Number of context lines around code slices (default: 8)."),
):
    """Scan a C++ repository for vulnerabilities."""
    
    # Load and update configuration
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    # Update config with CLI arguments
    config.max_cost = max_cost
    config.output_format = OutputFormat(format)
    config.llm_provider = provider
    config.debug = debug
    config.force_scan = force
    
    if output:
        config.output_path = output
    
    if model:
        config.llm_model = model
    
    if anthropic_version:
        config.anthropic_version = anthropic_version
    
    config.min_lines = min_lines
    config.context_lines = context_lines
    
    if max_lines:
        config.max_lines = max_lines
    
    if require_evidence:
        config.require_evidence = [pattern.strip() for pattern in require_evidence.split(',')]
    
    if min_severity_per_rule:
        rule_severities = {}
        for rule_severity in min_severity_per_rule.split(','):
            if '=' in rule_severity:
                rule, severity = rule_severity.strip().split('=', 1)
                rule_severities[rule.strip()] = severity.strip()
        config.min_severity_per_rule = rule_severities
    
    if only_rules:
        config.only_rules = [rule.strip() for rule in only_rules.split(',')]
    
    if parallel_workers is None:
        parallel_workers = min(8, multiprocessing.cpu_count())
    config.parallel_workers = parallel_workers
    
    # Map severity string to enum
    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL
    }
    config.min_severity = severity_map.get(min_severity.lower(), Severity.LOW)
    
    if cost_dry_run:
        print("Cost estimation mode - no actual scanning will be performed")
        print(f"LLM Provider: {config.llm_provider}")
        print(f"LLM Model: {config.llm_model}")
        if config.llm_provider == "anthropic":
            print(f"Anthropic Version: {config.anthropic_version}")
        print(f"Max Cost: ${config.max_cost}")
        print("Run without --cost-dry-run to perform actual scan")
        sys.exit(0)
    
    try:
        report = scan_repository(path, config)
        
        # Print summary
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(report.summary)
        
        # Only print detailed findings if no output file is specified (console mode)
        if not config.output_path and config.output_format == OutputFormat.CONSOLE:
            if report.findings:
                print("\n" + "="*50)
                print("VULNERABILITY FINDINGS")
                print("="*50)
                
                for i, finding in enumerate(report.findings, 1):
                    print(f"\n{i}. {finding.severity.value.upper()}: {finding.file_path}:{finding.line_number}")
                    print(f"   Rule: {finding.rule_id}")
                    print(f"   Description: {finding.description}")
                    if finding.taint_path:
                        print(f"   Taint Path: {' -> '.join(finding.taint_path)}")
                    print("-" * 30)
            else:
                print("\nNo vulnerabilities found!")
        
        # Save output if specified
        if config.output_path:
            _save_output(report, config)
        
    except Exception as e:
        print(f"Scan failed: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

@app.command()
def config():
    """Show current configuration."""
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    print("Current MemSage Configuration:")
    print("="*40)
    print(f"LLM Provider: {config.llm_provider}")
    print(f"LLM Model: {config.llm_model}")
    if config.llm_provider == "anthropic":
        print(f"Anthropic Version: {config.anthropic_version}")
    print(f"Max Cost: ${config.max_cost}")
    print(f"Min Severity: {config.min_severity.value}")
    print(f"Output Format: {config.output_format.value}")
    print(f"Debug Mode: {config.debug}")
    print(f"Force Scan: {config.force_scan}")

def _save_output(report, config):
    """Save report to file based on output format."""
    try:
        if config.output_format == OutputFormat.JSON:
            import json
            output_data = {
                "findings": [
                    {
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "description": f.description,
                        "taint_path": f.taint_path
                    }
                    for f in report.findings
                ],
                "summary": {
                    "total_files_scanned": report.total_files_scanned,
                    "total_findings": report.total_findings,
                    "scan_duration": report.scan_duration,
                    "critical_count": report.critical_count,
                    "high_count": report.high_count,
                    "medium_count": report.medium_count,
                    "low_count": report.low_count
                }
            }
            
            with open(config.output_path, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"\nJSON report saved to: {config.output_path}")
            
        elif config.output_format == OutputFormat.SARIF:
            from .exporters import SARIFExporter
            exporter = SARIFExporter(config)
            exporter.export(report, Path(config.output_path))
            print(f"\nSARIF report saved to: {config.output_path}")
            

            
    except Exception as e:
        print(f"Warning: Could not save output to {config.output_path}: {e}")

if __name__ == "__main__":
    app() 