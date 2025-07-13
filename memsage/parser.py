"""
C++ code parser module for memsage.

This module handles C++ code parsing and AST extraction functionality.
It provides utilities for parsing C++ source files, extracting AST information,
and managing parsing sessions with proper error handling and configuration.
"""

import clang.cindex
from typing import List, Dict, Optional, Any, Set, Iterator
from pathlib import Path
import json
from dataclasses import dataclass, asdict
from enum import Enum
from rich.progress import Progress
from rich.console import Console

console = Console()


def walk_cpp_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if p.suffix in {".cpp", ".cc", ".c", ".hpp", ".h"} and p.is_file():
            yield p

def extract_functions(file_path: Path):
    # Minimal stub: just yields the file as a single function for demo
    yield {
        "file": file_path,
        "function_name": file_path.stem,
        "start_line": 1,
        "end_line": sum(1 for _ in open(file_path))
    } 