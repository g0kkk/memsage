# MemSage: LLM-Powered C++ Memory Safety Vulnerability Detection

## Overview

MemSage is a Python prototype for LLM-powered C++ memory safety vulnerability detection, designed with cost control, intelligent code slicing, and pluggable LLM backends. The system focuses on high-confidence vulnerability detection through targeted analysis of dangerous API usage patterns.

## Architecture

### Core Components

1. **Code Slicer** (`slicer.py`)
   - Extracts code slices containing dangerous API calls
   - Uses both libclang AST analysis and regex fallback
   - Configurable context lines around vulnerable code
   - Filters by minimum/maximum slice size

2. **LLM Analyzer** (`llm.py`)
   - Pluggable backend system (Anthropic Claude, Ollama)
   - Parallel processing with configurable workers
   - Cost estimation and tracking
   - Retry logic with exponential backoff

3. **Scan Engine** (`scan.py`)
   - Orchestrates the scanning pipeline
   - Applies filtering rules (evidence patterns, severity thresholds)
   - Manages cost limits and abort conditions
   - Generates comprehensive reports

4. **Report Generation** (`exporters.py`)
   - SARIF format with CWE mappings
   - Rich metadata (quick fixes, help URIs, line hashes)
   - Deduplication and severity aggregation
   - Deterministic output for CI/CD integration

### Design Principles

#### 1. Cost-Aware Analysis
- **Token estimation** before scanning to prevent budget overruns
- **Parallel processing** to maximize throughput within cost limits
- **Configurable cost ceilings** with force override options
- **Real-time cost tracking** during analysis

#### 2. Intelligent Code Slicing
- **Targeted extraction** of dangerous API usage patterns
- **Context preservation** with configurable line ranges
- **Size filtering** to avoid analyzing irrelevant code blocks
- **Evidence-based filtering** to focus on high-confidence patterns

#### 3. Pluggable LLM Backends
- **Anthropic Claude** for high-quality analysis
- **Ollama** for local/offline processing
- **Unified interface** for easy backend switching
- **Version fallback** for API compatibility

#### 4. High-Confidence Results
- **Rule-specific severity thresholds** to filter low-confidence findings
- **Evidence pattern matching** to ensure relevant code analysis
- **Deduplication** to avoid duplicate reports
- **Rich metadata** for actionable remediation

## Implementation Approach

### Code Slicing Strategy

```python
# Two-phase extraction approach
1. AST-based extraction using libclang
   - Precise function call identification
   - Context-aware vulnerability detection
   - Better handling of complex C++ constructs

2. Regex fallback for robustness
   - Pattern matching for dangerous APIs
   - Handles parsing errors gracefully
   - Ensures coverage even with problematic code
```

### LLM Integration

```python
# Structured prompt engineering
- Vulnerability type classification
- Severity assessment (critical/high/medium/low)
- Detailed description with context
- Actionable fix suggestions

# Cost optimization
- Token estimation based on slice size
- Parallel processing with semaphore limits
- Retry logic for rate limits and errors
- Real-time progress tracking
```

### Filtering Pipeline

```python
# Multi-stage filtering for precision
1. Size filtering (min/max lines)
2. Evidence pattern matching
3. LLM analysis and rule classification
4. Rule-specific severity thresholds
5. Deduplication and aggregation
```

### Report Generation

```python
# SARIF compliance with enhancements
- CWE (Common Weakness Enumeration) mappings
- Quick fix suggestions with code examples
- Help URIs for remediation guidance
- Deterministic line hashes for change tracking
- Severity distribution and summary statistics
```

## Key Features

### 1. Cost Control
- **Pre-scan estimation** prevents budget overruns
- **Parallel processing** maximizes efficiency
- **Configurable limits** with override options
- **Real-time tracking** during analysis

### 2. Intelligent Filtering
- **Evidence-based slicing** focuses on relevant code
- **Rule-specific thresholds** ensures high confidence
- **Size limits** avoids analyzing irrelevant blocks
- **Pattern matching** targets specific vulnerability types

### 3. Pluggable Architecture
- **Multiple LLM backends** (Anthropic, Ollama)
- **Configurable models** per provider
- **Version compatibility** with automatic fallback
- **Unified interface** for easy extension

### 4. Production-Ready Output
- **SARIF format** for tool integration
- **Rich metadata** for actionable results
- **Deduplication** to avoid noise
- **Deterministic output** for CI/CD

## Usage Patterns

### High-Confidence Scanning
```bash
# Focus on specific vulnerability types with evidence
poetry run memsage scan libtiff \
  --only-rules buffer-overflow,use-after-free \
  --require-evidence "strcpy|memcpy|free|delete" \
  --min-severity-per-rule "buffer-overflow=high,use-after-free=high" \
  --max-cost 5 \
  --format sarif
```

### Cost-Conscious Analysis
```bash
# Use local Ollama for zero-cost analysis
poetry run memsage scan project \
  --provider ollama \
  --model mistral:latest \
  --parallel-workers 4 \
  --min-lines 3 \
  --max-lines 50
```

### CI/CD Integration
```bash
# Generate SARIF for security tools
poetry run memsage scan src \
  --format sarif \
  --output security-report.sarif \
  --max-cost 10 \
  --min-severity high
```

## Technical Decisions

### 1. Python Implementation
- **Rapid prototyping** for LLM integration
- **Rich ecosystem** for C++ parsing (libclang)
- **Easy deployment** with Poetry dependency management
- **Extensible architecture** for future enhancements

### 2. libclang Integration
- **Precise AST analysis** for accurate slicing
- **C++ standard compliance** for modern codebases
- **Error handling** with regex fallback
- **Performance optimization** for large codebases

### 3. SARIF Output
- **Industry standard** for security tool integration
- **Rich metadata** support for actionable results
- **CI/CD compatibility** with existing security pipelines
- **Extensible format** for future enhancements

### 4. Parallel Processing
- **asyncio-based** for efficient I/O handling
- **Configurable workers** for resource optimization
- **Thread-safe** cost tracking and result aggregation
- **Progress reporting** for long-running scans

## Future Enhancements

### 1. Advanced Analysis
- **Taint analysis** for data flow tracking
- **Interprocedural analysis** for cross-function vulnerabilities
- **Symbolic execution** for deeper code understanding
- **Machine learning** for pattern recognition

### 2. Extended Language Support
- **C language** support for legacy codebases
- **Rust integration** for memory safety verification
- **Go analysis** for concurrent memory issues
- **Java/C#** for managed language vulnerabilities

### 3. Enhanced LLM Integration
- **Multi-model ensemble** for improved accuracy
- **Fine-tuned models** for specific vulnerability types
- **Context window optimization** for large codebases
- **Incremental analysis** for changed code only

### 4. Production Features
- **Database integration** for result persistence
- **Web dashboard** for result visualization
- **API endpoints** for tool integration
- **Distributed scanning** for large codebases

## Conclusion

MemSage demonstrates the potential of LLM-powered static analysis for memory safety vulnerability detection. The combination of intelligent code slicing, cost-aware processing, and high-confidence filtering provides a practical approach to automated security analysis.

The pluggable architecture and SARIF output make it suitable for integration into existing security workflows, while the cost control mechanisms ensure practical deployment in real-world environments. 