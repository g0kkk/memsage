# MemSage: LLM-Powered C++ Memory Safety Vulnerability Detection

MemSage is a Python tool that uses large language models to detect memory safety vulnerabilities in C++ code. It combines intelligent code slicing with LLM analysis to find buffer overflows, use-after-free bugs, format string vulnerabilities, and other memory safety issues.

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd memsage

# Install dependencies
poetry install

# Set up your API key (for Anthropic)
export ANTHROPIC_API_KEY="your-api-key-here"
```

### Basic Usage

```bash
# Scan a C++ project with default settings
poetry run memsage scan /path/to/cpp/project

# Generate a SARIF report
poetry run memsage scan /path/to/cpp/project --format sarif --output results.sarif
```

## How It Works

MemSage works in three stages:

1. **Code Slicing**: Extracts code snippets containing dangerous API calls (like `strcpy`, `free`, `malloc`)
2. **LLM Analysis**: Sends these snippets to an LLM (Claude or Ollama) for vulnerability analysis
3. **Report Generation**: Produces detailed reports with vulnerability descriptions and fix suggestions

## Configuration Options

### LLM Providers

**Anthropic Claude** (recommended for high-quality analysis):
```bash
poetry run memsage scan project \
  --provider anthropic \
  --model claude-3-sonnet-20240229 \
  --max-cost 5
```

**Ollama** (free, local analysis):
```bash
poetry run memsage scan project \
  --provider ollama \
  --model mistral:latest
```

### Filtering Options

**Focus on specific vulnerability types:**
```bash
poetry run memsage scan project \
  --only-rules buffer-overflow,use-after-free,format-string
```

**Require specific evidence patterns:**
```bash
poetry run memsage scan project \
  --require-evidence "strcpy|memcpy|free|delete"
```

**Set minimum severity per rule:**
```bash
poetry run memsage scan project \
  --min-severity-per-rule "buffer-overflow=high,use-after-free=high"
```

**Limit slice size:**
```bash
poetry run memsage scan project \
  --min-lines 3 \
  --max-lines 50
```

### Performance Options

**Parallel processing:**
```bash
poetry run memsage scan project \
  --parallel-workers 8
```

**Cost control:**
```bash
poetry run memsage scan project \
  --max-cost 10 \
  --force  # Override cost limits
```

## Usage Examples

### High-Confidence Scanning

For focused, high-confidence results:

```bash
poetry run memsage scan libtiff \
  --provider anthropic \
  --model claude-3-sonnet-20240229 \
  --only-rules buffer-overflow,use-after-free \
  --min-severity-per-rule "buffer-overflow=high,use-after-free=high" \
  --require-evidence "strcpy|memcpy|free|delete" \
  --max-cost 5 \
  --format sarif \
  --output libtiff-security.sarif
```

### Comprehensive Analysis

For broad vulnerability detection:

```bash
poetry run memsage scan project \
  --provider anthropic \
  --model claude-3-sonnet-20240229 \
  --max-cost 20 \
  --format sarif \
  --output comprehensive-report.sarif
```

### Cost-Conscious Analysis

For zero-cost local analysis:

```bash
poetry run memsage scan project \
  --provider ollama \
  --model mistral:latest \
  --parallel-workers 4 \
  --min-lines 3 \
  --max-lines 50
```



## Understanding Filtering Options

### What happens when you remove filters?

**Without `--only-rules`:**
- Analyzes ALL vulnerability types (memory leaks, integer overflows, etc.)
- More comprehensive but potentially more expensive

**Without `--min-severity-per-rule`:**
- Includes ALL severities (low, medium, high, critical)
- More findings but some may be lower confidence

**Without `--require-evidence`:**
- Analyzes ALL code slices with dangerous APIs
- May significantly increase cost and analysis time
- Could exceed budget for large codebases

**Minimal command (no filtering):**
```bash
poetry run memsage scan project \
  --provider anthropic \
  --model claude-3-sonnet-20240229 \
  --max-cost 5
```
This will analyze everything but may exceed your budget.

## Output Formats

### Console Output
Default format showing findings in the terminal:
```
==================================================
VULNERABILITY FINDINGS
==================================================

1. HIGH: src/buffer.c:42
   Rule: buffer-overflow
   Description: Potential buffer overflow in strcpy call...
```

### SARIF Format
Industry-standard format for security tools:
```bash
poetry run memsage scan project --format sarif --output report.sarif
```

### JSON Format
Machine-readable output:
```bash
poetry run memsage scan project --format json --output report.json
```

## Cost Management

### Understanding Costs

- **Anthropic Claude Sonnet**: ~$3-15 per 1M tokens
- **Anthropic Claude Haiku**: ~$0.25-1.25 per 1M tokens
- **Ollama**: Free (local processing)

### Cost Estimation

MemSage estimates costs before scanning:
```
Estimated LLM cost: $0.0235
```

### Cost Control

```bash
# Set maximum cost
poetry run memsage scan project --max-cost 5

# Force scan even if cost limit exceeded
poetry run memsage scan project --max-cost 5 --force

# Dry run to see cost estimate only
poetry run memsage scan project --cost-dry-run
```

## Configuration File

Create `memsage.toml` for default settings:

```toml
[llm]
provider = "anthropic"
model = "claude-3-sonnet-20240229"

[scan]
max_cost = 10.0
parallel_workers = 8
min_lines = 3
max_lines = 100

[output]
format = "sarif"
```

## Troubleshooting

### Common Issues

**"ANTHROPIC_API_KEY not set"**
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

**"Ollama connection failed"**
```bash
# Start Ollama service
ollama serve

# Pull the model
ollama pull mistral:latest
```

**"Cost limit exceeded"**
```bash
# Increase budget
poetry run memsage scan project --max-cost 20

# Or use Ollama for free analysis
poetry run memsage scan project --provider ollama
```

**"No vulnerabilities found"**
- Try removing `--require-evidence` to analyze more code
- Lower `--min-severity-per-rule` thresholds
- Check if the project actually contains dangerous APIs

## Supported Vulnerability Types

- **Buffer Overflow**: `strcpy`, `memcpy`, `sprintf` without bounds checking
- **Use-After-Free**: `free`/`delete` followed by pointer access
- **Format String**: `printf` with user-controlled format strings
- **Memory Leak**: `malloc`/`new` without corresponding `free`/`delete`
- **Integer Overflow**: Arithmetic operations that can overflow
- **Null Pointer Dereference**: Accessing null pointers

## Requirements

- Python 3.8+
- Poetry for dependency management
- libclang for C++ parsing
- Anthropic API key (for Claude) or Ollama (for local analysis)

## License

MIT License - see LICENSE file for details. 