"""Enhanced slice extraction for memory safety vulnerabilities."""

import re
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass
from clang.cindex import Index, CursorKind, TranslationUnit
from .report import VulnerabilityFinding, Severity

# Enhanced dangerous APIs for memory safety
dangerous_apis = [
    # Buffer operations
    "strcpy", "strncpy", "sprintf", "vsprintf", "snprintf", "gets", "scanf", "sscanf",
    "memcpy", "memmove", "strcat", "strncat", "streadd", "strecpy",
    
    # Memory management
    "malloc", "free", "realloc", "calloc", "delete", "delete[]",
    
    # System calls
    "system", "popen", "exec", "execl", "execv", "execvp", "execlp", "execle",
    
    # Format strings
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
    
    # File operations (potential path traversal)
    "fopen", "open", "creat", "mkstemp", "tmpfile",
    
    # Network (potential injection)
    "recv", "send", "read", "write"
]

# Memory safety patterns
memory_patterns = [
    r'delete\s+\w+;\s*.*\w+\[',  # delete followed by array access
    r'free\s*\(\s*\w+\s*\);\s*.*\w+\[',  # free followed by array access
    r'delete\s+\w+;\s*.*\w+->',  # delete followed by pointer access
    r'free\s*\(\s*\w+\s*\);\s*.*\w+->',  # free followed by pointer access
    r'\w+\s*\[\s*\w+\s*\]\s*=\s*\w+',  # array assignment without bounds check
    r'strcpy\s*\(\s*\w+\s*,\s*\w+\s*\)',  # strcpy without size check
    r'printf\s*\(\s*\w+\s*\)',  # printf with user input
    r'scanf\s*\(\s*"[^"]*"\s*,\s*\w+\s*\)',  # scanf without bounds
]

@dataclass
class SliceTask:
    file_path: str
    start_line: int
    end_line: int
    code: str
    danger_api: str
    function_name: str
    severity: Severity
    context: str = ""
    pattern_matched: str = ""

class SliceExtractor:
    """Enhanced extractor for memory safety vulnerabilities."""
    
    def __init__(self, debug: bool = False, context_lines: int = 8):
        self.debug = debug
        self.context_lines = context_lines
        self.index = Index.create()
    
    def extract_slices(self, file_path: Path) -> List[SliceTask]:
        if self.debug:
            print(f"Extracting slices from: {file_path}")

        slices = []
        ast_slices = []
        try:
            ast_slices = self._extract_ast_slices(file_path)
            if self.debug:
                print(f"  AST extraction found {len(ast_slices)} slices")
            slices.extend(ast_slices)
        except Exception as e:
            if self.debug:
                print(f"AST extraction failed: {e}")

        # If AST found nothing, always try regex as fallback
        if not ast_slices:
            regex_slices = self._extract_regex_slices(file_path)
            if self.debug:
                print(f"  Regex extraction found {len(regex_slices)} slices")
            slices.extend(regex_slices)

        if self.debug:
            print(f"Found {len(slices)} total slices in {file_path}")
            for slice in slices:
                print(f"  Line {slice.start_line}: {slice.danger_api} - {slice.code[:50]}...")

        return slices
    
    def _extract_ast_slices(self, file_path: Path) -> List[SliceTask]:
        """Extract slices using libclang AST analysis."""
        slices = []
        
        # Read the source file first
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        lines = f.readlines()
                    break
                except UnicodeDecodeError:
                    continue
            else:
                # If all encodings fail, skip this file
                if self.debug:
                    print(f"  Could not read file {file_path} with any encoding")
                return []
        
        # Parse the file
        tu = self.index.parse(str(file_path), args=['-std=c++17', '-x', 'c++'])
        
        def visit_node(cursor, parent):
            if cursor.kind == CursorKind.CALL_EXPR:
                # Check if this is a dangerous API call
                func_name = cursor.spelling
                if func_name in dangerous_apis:
                    # Get the source location
                    location = cursor.location
                    if location.file and str(location.file) == str(file_path):
                        # Get the function containing this call
                        func_cursor = cursor
                        while func_cursor and func_cursor.kind != CursorKind.FUNCTION_DECL:
                            func_cursor = func_cursor.semantic_parent
                        
                        function_name = func_cursor.spelling if func_cursor else "unknown"
                        
                        # Get the source code around this call
                        start_line = location.line
                        end_line = location.line
                        
                        if start_line <= len(lines):
                            code_line = lines[start_line - 1].strip()
                            
                            # Determine severity based on API
                            severity = self._get_severity(func_name)
                            
                            # Get context (function or block)
                            context = self._get_context(lines, start_line, function_name)
                            
                            slices.append(SliceTask(
                                file_path=str(file_path),
                                start_line=start_line,
                                end_line=end_line,
                                code=code_line,
                                danger_api=func_name,
                                function_name=function_name,
                                severity=severity,
                                context=context,
                                pattern_matched="AST"
                            ))
            
            return True
        
        # Traverse the AST
        for cursor in tu.cursor.walk_preorder():
            visit_node(cursor, None)
        return slices
    
    def _extract_regex_slices(self, file_path: Path) -> List[SliceTask]:
        """Extract slices using regex pattern matching."""
        slices = []
        
        if self.debug:
            print(f"  Reading file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            # Try with different encodings
            for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        lines = f.readlines()
                    break
                except UnicodeDecodeError:
                    continue
            else:
                # If all encodings fail, skip this file
                if self.debug:
                    print(f"  Could not read file {file_path} with any encoding")
                return []
        
        if self.debug:
            print(f"  Read {len(lines)} lines from file")
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            # Print for debug
            if self.debug:
                print(f"Checking line {i}: {line_stripped}")
            for api in dangerous_apis:
                # Loosen: match api followed by '(' anywhere in the line
                if f"{api}(" in line_stripped or re.search(rf'\b{re.escape(api)}\b', line_stripped):
                    if self.debug:
                        print(f"  Matched {api} in line {i}: {line_stripped}")
                    function_name = self._extract_function_name(lines, i)
                    severity = self._get_severity(api)
                    context = self._get_context(lines, i, function_name)
                    slices.append(SliceTask(
                        file_path=str(file_path),
                        start_line=i,
                        end_line=i,
                        code=line_stripped,
                        danger_api=api,
                        function_name=function_name,
                        severity=severity,
                        context=context,
                        pattern_matched="regex"
                    ))
        
        if self.debug:
            print(f"  Found {len(slices)} slices via regex")
        
        return slices
    
    def _get_severity(self, api: str) -> Severity:
        """Determine severity based on the dangerous API."""
        critical_apis = ["strcpy", "gets", "sprintf", "system", "exec", "printf"]
        high_apis = ["strncpy", "memcpy", "scanf", "fopen", "malloc", "free", "delete"]
        
        if api in critical_apis:
            return Severity.CRITICAL
        elif api in high_apis:
            return Severity.HIGH
        else:
            return Severity.MEDIUM
    
    def _extract_function_name(self, lines: List[str], line_num: int) -> str:
        """Extract function name containing the given line."""
        # Simple heuristic: look for function declaration above this line
        for i in range(line_num - 1, max(0, line_num - 10), -1):
            line = lines[i].strip()
            # Look for function declaration patterns
            if re.match(r'\w+\s+\w+\s*\([^)]*\)\s*\{?$', line):
                match = re.search(r'(\w+)\s*\([^)]*\)', line)
                if match:
                    return match.group(1)
        return "unknown"
    
    def _get_context(self, lines: List[str], line_num: int, function_name: str) -> str:
        """Get context around the vulnerable line."""
        start = max(0, line_num - self.context_lines)
        end = min(len(lines), line_num + self.context_lines)
        context_lines = lines[start:end]
        return ''.join(context_lines)
    
    def estimate_token_cost(self, slices: List[SliceTask]) -> float:
        """Estimate token cost for LLM analysis."""
        total_tokens = 0
        for slice in slices:
            # Rough token estimation: 1 token ~ 4 characters
            code_tokens = len(slice.code) // 4
            context_tokens = len(slice.context) // 4
            total_tokens += code_tokens + context_tokens + 100  # Prompt overhead
        
        # Claude Haiku pricing: $0.25 per 1M input tokens
        cost_per_token = 0.25 / 1_000_000
        return total_tokens * cost_per_token 