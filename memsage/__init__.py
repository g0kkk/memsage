"""
Memsage - C++ vulnerability detection tool

A comprehensive tool for static analysis of C++ code to detect
vulnerabilities using advanced AI models and interprocedural analysis.
"""

__version__ = "0.9.0"
__author__ = "Gokul Krishna P"
__email__ = "gkgokulkrishna33@gmail.com"

# Import main modules
from .parser import walk_cpp_files
from .slicer import SliceExtractor, SliceTask
from .report import VulnerabilityFinding, VulnerabilityReport, Severity
from .scan import scan_repository
from .config import ScanConfig, ConfigManager, OutputFormat
from .exporters import ExportManager, SARIFExporter
from .cli import app

__all__ = [
    # Core classes
    "SliceExtractor",
    "ExportManager",
    
    # Data classes
    "SliceTask",
    "VulnerabilityFinding",
    "VulnerabilityReport",
    "ScanConfig",
    
    # Enums
    "Severity",
    "OutputFormat",
    
    # Functions
    "walk_cpp_files",
    "scan_repository",
    
    # Configuration
    "ConfigManager",
    
    # Exporters
    "SARIFExporter",
    
    # CLI
    "app"
] 