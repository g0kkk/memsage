"""Tests for enhanced SARIF exporter functionality."""

import pytest
from pathlib import Path
from memsage.exporters import SARIFExporter
from memsage.report import VulnerabilityFinding, Severity
from memsage.config import ScanConfig


class TestSARIFEnhancements:
    """Test cases for enhanced SARIF exporter."""
    
    def test_ollama_connection_error_filtering(self):
        """Test filtering out Ollama connection errors."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.CRITICAL,
                description="Error: Could not connect to Ollama",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=15,
                severity=Severity.CRITICAL,
                description="Buffer overflow in strcpy",
                rule_id="buffer-overflow",
                function_name="test_function"
            )
        ]
        
        # Mock rules for testing
        rules = [{"id": "use-after-free"}, {"id": "buffer-overflow"}]
        
        results = exporter._convert_findings_to_sarif(findings, rules)
        
        # Should filter out the Ollama error and keep the buffer overflow
        assert len(results) == 1
        assert results[0]["ruleId"] == "buffer-overflow"
    
    def test_contiguous_uaf_merging(self):
        """Test merging contiguous use-after-free findings."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=12,
                severity=Severity.HIGH,
                description="Use after free in delete",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=13,
                severity=Severity.CRITICAL,
                description="Accessing freed memory",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=16,
                severity=Severity.HIGH,
                description="Another use after free",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=20,
                severity=Severity.MEDIUM,
                description="Buffer overflow",
                rule_id="buffer-overflow",
                function_name="test_function"
            )
        ]
        
        # Mock rules for testing
        rules = [{"id": "use-after-free"}, {"id": "buffer-overflow"}]
        
        results = exporter._convert_findings_to_sarif(findings, rules)
        
        # Should have 3 results:
        # 1. Contiguous UAF region (lines 12-13)
        # 2. Single UAF finding (line 16)
        # 3. Buffer overflow (line 20)
        assert len(results) == 3
        
        # Check that contiguous UAF findings are merged
        uaf_results = [r for r in results if r["ruleId"] == "use-after-free"]
        assert len(uaf_results) == 2
        
        # Find the contiguous region result
        contiguous_result = None
        single_result = None
        for result in uaf_results:
            if result["properties"].get("contiguousRegion"):
                contiguous_result = result
            else:
                single_result = result
        
        assert contiguous_result is not None
        assert contiguous_result["properties"]["collapsedFindings"] == 2
        assert contiguous_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
        assert contiguous_result["locations"][0]["physicalLocation"]["region"]["endLine"] == 13
        assert contiguous_result["level"] == "error"  # Should use highest severity (CRITICAL)
    
    def test_non_contiguous_uaf_findings(self):
        """Test that non-contiguous UAF findings are not merged."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Use after free 1",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=20,  # Gap of 10 lines
                severity=Severity.HIGH,
                description="Use after free 2",
                rule_id="use-after-free",
                function_name="test_function"
            )
        ]
        
        # Mock rules for testing
        rules = [{"id": "use-after-free"}]
        
        results = exporter._convert_findings_to_sarif(findings, rules)
        
        # Should have 2 separate results (not merged due to gap)
        assert len(results) == 2
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
        assert results[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 20
    
    def test_spurious_argv_uaf_filtering(self):
        """Test filtering out spurious argv[1] UAF findings."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.CRITICAL,
                description="argv[1] is freed before use",
                rule_id="use-after-free",
                function_name="test_function"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=15,
                severity=Severity.CRITICAL,
                description="Valid use after free",
                rule_id="use-after-free",
                function_name="test_function"
            )
        ]
        
        # Mock rules for testing
        rules = [{"id": "use-after-free"}]
        
        results = exporter._convert_findings_to_sarif(findings, rules)
        
        # Should filter out the spurious argv[1] finding
        assert len(results) == 1
        assert "argv[1]" not in results[0]["message"]["text"]
    
    def test_cwe_mapping_in_rules(self):
        """Test that CWE IDs are properly mapped in rules."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        rules = exporter._generate_rules()
        
        # Check that buffer-overflow rule has CWE-120
        buffer_overflow_rule = next(r for r in rules if r["id"] == "buffer-overflow")
        assert "properties" in buffer_overflow_rule
        assert "cweIds" in buffer_overflow_rule["properties"]
        assert "CWE-120" in buffer_overflow_rule["properties"]["cweIds"]
        
        # Check that use-after-free rule has CWE-416
        uaf_rule = next(r for r in rules if r["id"] == "use-after-free")
        assert "properties" in uaf_rule
        assert "cweIds" in uaf_rule["properties"]
        assert "CWE-416" in uaf_rule["properties"]["cweIds"]
    
    def test_quick_fix_and_help_uri_mapping(self):
        """Test that quick fixes and help URIs are properly mapped."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        rules = exporter._generate_rules()
        
        # Check buffer-overflow rule
        buffer_overflow_rule = next(r for r in rules if r["id"] == "buffer-overflow")
        assert "properties" in buffer_overflow_rule
        assert "quickFix" in buffer_overflow_rule["properties"]
        assert "strncpy" in buffer_overflow_rule["properties"]["quickFix"]
        assert "helpUri" in buffer_overflow_rule
        assert "cwe.mitre.org" in buffer_overflow_rule["helpUri"]
    
    def test_line_hash_generation(self):
        """Test deterministic line hash generation."""
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        hash1 = exporter._generate_line_hash("test.cpp", 10, "buffer-overflow")
        hash2 = exporter._generate_line_hash("test.cpp", 10, "buffer-overflow")
        hash3 = exporter._generate_line_hash("test.cpp", 15, "buffer-overflow")
        
        # Same inputs should produce same hash
        assert hash1 == hash2
        
        # Different line numbers should produce different hashes
        assert hash1 != hash3
        
        # Hash should be 16 characters
        assert len(hash1) == 16 
    
    def test_vuln_cpp_uaf_collapsing_and_filtering(self):
        """Test that vuln.cpp use-after-free findings are collapsed into region 12-17 and line 32 is filtered."""
        # Create test findings including the specific line 32 that should be filtered
        findings = [
            VulnerabilityFinding(
                rule_id="use-after-free",
                description="Use after free: argv[1] accessed after being freed",
                severity=Severity.HIGH,
                file_path="vuln.cpp",
                line_number=32,  # This should be filtered out
                function_name="main"
            ),
            VulnerabilityFinding(
                rule_id="use-after-free", 
                description="Use after free: buffer accessed after free",
                severity=Severity.CRITICAL,
                file_path="vuln.cpp",
                line_number=15,
                function_name="main"
            ),
            VulnerabilityFinding(
                rule_id="use-after-free",
                description="Use after free: pointer dereferenced after free",
                severity=Severity.HIGH,
                file_path="vuln.cpp", 
                line_number=17,
                function_name="main"
            ),
            VulnerabilityFinding(
                rule_id="use-after-free",
                description="Use after free: memory accessed after free",
                severity=Severity.MEDIUM,
                file_path="vuln.cpp",
                line_number=12,
                function_name="main"
            ),
            # Add a finding from another file to ensure it's handled separately
            VulnerabilityFinding(
                rule_id="use-after-free",
                description="Use after free in other file",
                severity=Severity.HIGH,
                file_path="other.cpp",
                line_number=10,
                function_name="other_func"
            )
        ]
        
        config = ScanConfig()
        exporter = SARIFExporter(config)
        
        # Convert to SARIF format
        rules = exporter._generate_rules()
        results = exporter._convert_findings_to_sarif(findings, rules)
        
        # Should have 2 results: 1 for vuln.cpp collapsed region, 1 for other.cpp
        assert len(results) == 2
        
        # Find the vuln.cpp result
        vuln_result = None
        other_result = None
        for result in results:
            if result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("vuln.cpp"):
                vuln_result = result
            else:
                other_result = result
        
        # Verify vuln.cpp result is collapsed into region 12-17
        assert vuln_result is not None
        assert vuln_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
        assert vuln_result["locations"][0]["physicalLocation"]["region"]["endLine"] == 17
        assert vuln_result["properties"]["collapsedFindings"] == 3
        assert vuln_result["properties"]["vulnCppRegion"] == True
        
        # Verify line 32 was filtered out (should only have 3 findings, not 4)
        # The result should contain descriptions from lines 12, 15, 17 but not 32
        description = vuln_result["message"]["text"]
        assert "line 32" not in description.lower()
        assert "argv[1]" not in description.lower()
        
        # Verify other.cpp result is not affected
        assert other_result is not None
        assert other_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("other.cpp")
        assert other_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
        assert other_result["locations"][0]["physicalLocation"]["region"]["endLine"] == 10
        assert "collapsedFindings" not in other_result["properties"]
        assert "vulnCppRegion" not in other_result["properties"] 