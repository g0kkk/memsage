"""
Tests to verify that all dependencies can be imported successfully.
"""

import pytest


def test_typer_import():
    """Test that typer can be imported."""
    import typer
    assert typer is not None


def test_pydantic_import():
    """Test that pydantic can be imported."""
    import pydantic
    assert pydantic is not None


def test_python_dotenv_import():
    """Test that python-dotenv can be imported."""
    import dotenv
    assert dotenv is not None


def test_anthropic_import():
    """Test that anthropic can be imported."""
    import anthropic
    assert anthropic is not None


def test_tqdm_import():
    """Test that tqdm can be imported."""
    import tqdm
    assert tqdm is not None


def test_rich_import():
    """Test that rich can be imported."""
    import rich
    assert rich is not None


def test_libclang_import():
    """Test that libclang can be imported."""
    import clang
    assert clang is not None


def test_requests_import():
    """Test that requests can be imported."""
    import requests
    assert requests is not None 