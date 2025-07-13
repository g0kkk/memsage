"""Configuration management for MemSage."""

import os
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum
from .report import Severity


class OutputFormat(Enum):
    """Supported output formats."""
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


@dataclass
class ScanConfig:
    """Configuration for vulnerability scanning."""
    
    # LLM Configuration
    llm_provider: str = "ollama"  # "ollama" or "anthropic"
    llm_model: str = "codellama:7b"  # Model to use
    max_cost: float = 50.0  # Maximum cost in USD
    anthropic_version: str = "2023-06-01"  # Anthropic API version
    
    # Scanning Configuration
    min_severity: Severity = Severity.LOW
    max_file_size_mb: float = 10.0
    parallel_workers: int = 4
    timeout_seconds: int = 300
    min_lines: int = 3  # Minimum lines for a code slice to be analyzed
    max_lines: Optional[int] = None  # Maximum lines for a code slice to be analyzed
    context_lines: int = 8  # Number of context lines around code slices
    require_evidence: List[str] = field(default_factory=list)  # Regex patterns that must match in slice
    min_severity_per_rule: Dict[str, str] = field(default_factory=dict)  # Rule-specific severity thresholds
    only_rules: List[str] = field(default_factory=list)  # Only check specific rules
    
    # File Filtering
    include_patterns: List[str] = field(default_factory=lambda: ["*.cpp", "*.cc", "*.c", "*.h", "*.hpp"])
    exclude_patterns: List[str] = field(default_factory=lambda: ["*test*", "*mock*", "*stub*"])
    exclude_dirs: List[str] = field(default_factory=lambda: ["build", "test", "tests", "vendor", "third_party"])
    
    # Output Configuration
    output_format: OutputFormat = OutputFormat.CONSOLE
    output_path: Optional[str] = None
    debug: bool = False
    
    # Advanced Options
    force_scan: bool = False  # Override cost limits


class ConfigManager:
    """Manages configuration loading and validation."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path("memsage.toml")
        self._config = None
    
    def get_config(self) -> ScanConfig:
        """Get the current configuration."""
        if self._config is None:
            self._config = self._load_config()
        return self._config
    
    def _load_config(self) -> ScanConfig:
        """Load configuration from file and environment."""
        config = ScanConfig()
        
        # Load from environment variables
        config.llm_provider = os.getenv("LLM_PROVIDER", os.getenv("MEMSAGE_LLM_PROVIDER", config.llm_provider))
        config.llm_model = os.getenv("MEMSAGE_LLM_MODEL", config.llm_model)
        config.max_cost = float(os.getenv("MEMSAGE_MAX_COST", str(config.max_cost)))
        config.anthropic_version = os.getenv("ANTHROPIC_VERSION", config.anthropic_version)
        config.debug = os.getenv("MEMSAGE_DEBUG", "false").lower() == "true"
        config.force_scan = os.getenv("MEMSAGE_FORCE_SCAN", "false").lower() == "true"
        
        # Load from TOML file if it exists
        if self.config_path.exists():
            try:
                import toml
                with open(self.config_path, 'r') as f:
                    toml_config = toml.load(f)
                
                # Update config with TOML values
                if "scan" in toml_config:
                    scan_config = toml_config["scan"]
                    config.max_cost = scan_config.get("max_cost", config.max_cost)
                    config.parallel_workers = scan_config.get("parallel_workers", config.parallel_workers)
                    config.min_severity = Severity(scan_config.get("min_severity", config.min_severity.value))
                    config.max_file_size_mb = scan_config.get("max_file_size_mb", config.max_file_size_mb)
                    config.min_lines = scan_config.get("min_lines", config.min_lines)
                    config.require_evidence = scan_config.get("require_evidence", config.require_evidence)
                    config.min_severity_per_rule = scan_config.get("min_severity_per_rule", config.min_severity_per_rule)
                
                if "llm" in toml_config:
                    llm_config = toml_config["llm"]
                    config.llm_provider = llm_config.get("provider", config.llm_provider)
                    config.llm_model = llm_config.get("model", config.llm_model)
                    config.anthropic_version = llm_config.get("anthropic_version", config.anthropic_version)
                
                if "output" in toml_config:
                    output_config = toml_config["output"]
                    config.output_format = OutputFormat(output_config.get("format", config.output_format.value))
                    config.output_path = output_config.get("path", config.output_path)
                
            except Exception as e:
                print(f"Warning: Could not load config from {self.config_path}: {e}")
        
        return config
    
    def save_config(self, config: ScanConfig) -> None:
        """Save configuration to file."""
        try:
            import toml
            
            toml_config = {
                "scan": {
                    "max_cost": config.max_cost,
                    "parallel_workers": config.parallel_workers,
                    "min_severity": config.min_severity.value,
                    "max_file_size_mb": config.max_file_size_mb,
                    "min_lines": config.min_lines,
                    "require_evidence": config.require_evidence,
                    "min_severity_per_rule": config.min_severity_per_rule,
                },
                "llm": {
                    "provider": config.llm_provider,
                    "model": config.llm_model,
                    "anthropic_version": config.anthropic_version,
                },
                "output": {
                    "format": config.output_format.value,
                    "path": config.output_path,
                }
            }
            
            with open(self.config_path, 'w') as f:
                toml.dump(toml_config, f)
                
        except Exception as e:
            print(f"Warning: Could not save config to {self.config_path}: {e}")
    
    def validate_config(self, config: ScanConfig) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []
        
        if config.max_cost <= 0:
            errors.append("max_cost must be positive")
        
        if config.parallel_workers <= 0:
            errors.append("parallel_workers must be positive")
        
        if config.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        if config.llm_provider not in ["ollama", "anthropic"]:
            errors.append("llm_provider must be 'ollama' or 'anthropic'")
        
        if config.output_format not in OutputFormat:
            errors.append(f"output_format must be one of {[f.value for f in OutputFormat]}")
        
        return errors 