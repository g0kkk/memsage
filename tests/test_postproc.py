"""Tests for post-processing module."""

import pytest
from memsage.postproc import PostProcessor, PostProcessingConfig
from memsage.report import VulnerabilityFinding, Severity


class TestPostProcessor:
    """Test cases for PostProcessor class."""
    
    def test_init(self):
        """Test PostProcessor initialization."""
        processor = PostProcessor()
        assert processor is not None
        assert processor.config.deduplicate is True
    
    def test_deduplicate_same_location_same_rule(self):
        """Test deduplication of findings with same file, line, and ruleId."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Buffer overflow in strcpy",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp", 
                line_number=10,
                severity=Severity.CRITICAL,
                description="Use after free in delete",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=15,
                severity=Severity.MEDIUM,
                description="Format string vulnerability",
                rule_id="format-string"
            )
        ]
        
        processor = PostProcessor()
        result = processor._deduplicate(findings)
        
        # Should merge the first two findings (same file, line, ruleId)
        # and keep the third one separate
        assert len(result) == 2
        
        # Check that the merged finding has the highest severity
        merged_finding = next(f for f in result if f.file_path == "test.cpp" and f.line_number == 10)
        assert merged_finding.severity == Severity.CRITICAL
        assert merged_finding.rule_id == "buffer-overflow"
        assert "Buffer overflow" in merged_finding.description
        assert "Use after free" in merged_finding.description
    
    def test_deduplicate_different_locations(self):
        """Test that findings at different locations are not merged."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Buffer overflow",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=20,
                severity=Severity.HIGH,
                description="Buffer overflow",
                rule_id="buffer-overflow"
            )
        ]
        
        processor = PostProcessor()
        result = processor._deduplicate(findings)
        
        # Should not merge findings at different lines
        assert len(result) == 2
    
    def test_deduplicate_different_rules(self):
        """Test that findings with different ruleIds are not merged."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Buffer overflow",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Use after free",
                rule_id="use-after-free"
            )
        ]
        
        processor = PostProcessor()
        result = processor._deduplicate(findings)
        
        # Should not merge findings with different ruleIds
        assert len(result) == 2
    
    def test_merge_findings(self):
        """Test merging multiple findings into one."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.MEDIUM,
                description="First description",
                rule_id="buffer-overflow",
                taint_path=["source1", "sink1"]
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.CRITICAL,
                description="Second description",
                rule_id="buffer-overflow",
                taint_path=["source2", "sink2"]
            )
        ]
        
        processor = PostProcessor()
        merged = processor._merge_findings(findings)
        
        assert merged.file_path == "test.cpp"
        assert merged.line_number == 10
        assert merged.severity == Severity.CRITICAL  # Highest severity
        assert merged.rule_id == "buffer-overflow"
        assert "First description" in merged.description
        assert "Second description" in merged.description
        assert len(merged.taint_path) == 4  # Combined taint paths
        assert "source1" in merged.taint_path
        assert "source2" in merged.taint_path
    
    def test_filter_by_severity(self):
        """Test filtering findings by minimum severity."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.LOW,
                description="Low severity",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=20,
                severity=Severity.HIGH,
                description="High severity",
                rule_id="use-after-free"
            )
        ]
        
        config = PostProcessingConfig(min_severity=Severity.MEDIUM)
        processor = PostProcessor(config)
        result = processor._filter_by_severity(findings)
        
        # Should only keep HIGH severity finding
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH
    
    def test_limit_per_file(self):
        """Test limiting findings per file."""
        findings = [
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=10,
                severity=Severity.HIGH,
                description="Finding 1",
                rule_id="buffer-overflow"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=20,
                severity=Severity.HIGH,
                description="Finding 2",
                rule_id="use-after-free"
            ),
            VulnerabilityFinding(
                file_path="test.cpp",
                line_number=30,
                severity=Severity.HIGH,
                description="Finding 3",
                rule_id="format-string"
            )
        ]
        
        config = PostProcessingConfig(max_findings_per_file=2)
        processor = PostProcessor(config)
        result = processor._limit_per_file(findings)
        
        # Should only keep first 2 findings
        assert len(result) == 2
        assert result[0].line_number == 10
        assert result[1].line_number == 20


# Note: Deduplicator class was removed in favor of integrated deduplication in PostProcessor 