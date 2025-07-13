"""LLM integration for vulnerability analysis."""

import json
import time
import subprocess
import requests
import os
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from rich.console import Console
from rich.progress import Progress
import asyncio
import threading

console = Console()


class LLMProvider(Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


@dataclass
class LLMResponse:
    """Response from an LLM."""
    content: str
    model: str
    provider: LLMProvider
    tokens_used: int
    response_time: float
    metadata: Dict[str, Any]


class LLMClient:
    """Base class for LLM clients."""
    
    def __init__(self, model: str = "claude-3-haiku-20240307"):
        self.model = model
        self.total_tokens = 0
        self.total_cost = 0.0
    
    def analyze_slice(self, code_slice: str, context: str = "") -> str:
        """Analyze a code slice for vulnerabilities."""
        raise NotImplementedError
    
    def get_cost_estimate(self, slices: List[str]) -> float:
        """Estimate cost for analyzing multiple slices."""
        raise NotImplementedError
    
    def get_total_cost(self) -> float:
        """Get total cost so far."""
        return self.total_cost


class OllamaClient(LLMClient):
    """Client for local Ollama models."""
    
    def __init__(self, model: str = "codellama:7b", base_url: str = "http://localhost:11434"):
        super().__init__(model)
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
    
    def analyze_slice(self, code_slice: str, context: str = "") -> str:
        """Analyze a code slice using Ollama."""
        prompt = self._build_prompt(code_slice, context)
        
        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "max_tokens": 500
                    }
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get("response", "")
                
                # Estimate tokens (rough approximation)
                tokens_used = len(prompt + content) // 4
                self.total_tokens += tokens_used
                
                return content
            else:
                return f"Error: Ollama API returned {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            return f"Error: Could not connect to Ollama at {self.base_url}: {e}"
    
    def _build_prompt(self, code_slice: str, context: str = "") -> str:
        """Build a prompt for vulnerability analysis."""
        return f"""You are a security expert analyzing C++ code for memory safety vulnerabilities.

Analyze the following code slice and identify any memory safety issues:

Code:
{code_slice}

Context:
{context}

Identify:
1. Type of vulnerability (buffer overflow, use-after-free, format string, etc.)
2. Severity (critical, high, medium, low)
3. Brief explanation of the issue
4. Suggested fix

Format your response as JSON:
{{
    "vulnerability_type": "string",
    "severity": "critical|high|medium|low",
    "description": "string",
    "suggested_fix": "string"
}}

Analysis:"""
    
    def get_cost_estimate(self, slices: List[str]) -> float:
        """Estimate cost for Ollama (free for local models)."""
        return 0.0


class AnthropicClient(LLMClient):
    """Client for Anthropic's Claude models."""
    
    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307", anthropic_version: str = None, version_source: str = "default"):
        super().__init__(model)
        self.api_key = api_key
        # Default to 2024-01-01, fallback to 2023-06-01 if needed
        self.default_version = "2024-01-01"
        self.fallback_version = "2023-06-01"
        self.version_source = version_source  # 'cli', 'env', or 'default'
        if anthropic_version is None:
            self.anthropic_version = self.default_version
        else:
            self.anthropic_version = anthropic_version
        try:
            import anthropic
            self.anthropic = anthropic
            self.client = anthropic.Anthropic(
                api_key=api_key,
                default_headers={"anthropic-version": self.anthropic_version}
            )
        except ImportError:
            raise ImportError("anthropic library not installed. Run: pip install anthropic")
    
    def _set_version(self, version):
        self.anthropic_version = version
        self.client = self.anthropic.Anthropic(
            api_key=self.api_key,
            default_headers={"anthropic-version": version}
        )
    
    def analyze_slice(self, code_slice: str, context: str = "") -> str:
        """Analyze a code slice using Claude."""
        prompt = self._build_prompt(code_slice, context)
        tried_fallback = False
        while True:
            try:
                start_time = time.time()
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=500,
                    temperature=0.1,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )
                response_time = time.time() - start_time
                content = response.content[0].text
                # Track token usage
                input_tokens = response.usage.input_tokens
                output_tokens = response.usage.output_tokens
                total_tokens = input_tokens + output_tokens
                self.total_tokens += total_tokens
                # Calculate cost
                cost = self._calculate_cost(input_tokens, output_tokens)
                self.total_cost += cost
                return content
            except Exception as e:
                error_msg = str(e)
                if ("invalid_request_error" in error_msg.lower() or "unsupported anthropic-version" in error_msg.lower()) and self.anthropic_version == self.default_version and self.version_source == "default" and not tried_fallback:
                    print(f"[memsage] Anthropic API version '{self.default_version}' is not supported for your account. Falling back to '{self.fallback_version}'.")
                    self._set_version(self.fallback_version)
                    tried_fallback = True
                    continue
                if "invalid_request_error" in error_msg.lower() or "unsupported anthropic-version" in error_msg.lower():
                    return (f"Error: Invalid Anthropic API version '{self.anthropic_version}'. "
                            f"Please specify a valid version using --anthropic-version or set ANTHROPIC_VERSION environment variable. "
                            f"Valid versions include: 2023-06-01, 2024-01-01, etc.")
                elif "rate_limit" in error_msg.lower():
                    return f"Error: Anthropic API rate limit exceeded. Please try again later."
                else:
                    return f"Error: Claude API call failed: {e}"
    
    def _build_prompt(self, code_slice: str, context: str = "") -> str:
        """Build a prompt for vulnerability analysis."""
        return f"""You are a security expert analyzing C++ code for memory safety vulnerabilities.

Analyze the following code slice and identify any memory safety issues:

Code:
{code_slice}

Context:
{context}

Identify:
1. Type of vulnerability (buffer overflow, use-after-free, format string, etc.)
2. Severity (critical, high, medium, low)
3. Brief explanation of the issue
4. Suggested fix

Format your response as JSON:
{{
    "vulnerability_type": "string",
    "severity": "critical|high|medium|low",
    "description": "string",
    "suggested_fix": "string"
}}

Analysis:"""
    
    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost based on model and token usage."""
        # Claude pricing (as of 2024)
        pricing = {
            "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},  # per 1M tokens
            "claude-3-sonnet-20240229": {"input": 3.0, "output": 15.0},   # per 1M tokens
            "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},    # per 1M tokens
        }
        
        model_pricing = pricing.get(self.model, pricing["claude-3-haiku-20240307"])
        
        input_cost = (input_tokens / 1_000_000) * model_pricing["input"]
        output_cost = (output_tokens / 1_000_000) * model_pricing["output"]
        
        return input_cost + output_cost
    
    def get_cost_estimate(self, slices: List[str]) -> float:
        """Estimate cost for Claude API calls."""
        total_input_tokens = 0
        total_output_tokens = 0
        
        for slice in slices:
            # Estimate input tokens (rough approximation: 1 token ~ 4 characters)
            slice_tokens = len(slice) // 4
            prompt_tokens = 200  # Base prompt overhead
            total_input_tokens += slice_tokens + prompt_tokens
            total_output_tokens += 100  # Estimated response size
        
        return self._calculate_cost(total_input_tokens, total_output_tokens)


class LLMAnalyzer:
    """Main LLM analyzer for vulnerability detection."""
    
    def __init__(self, provider: LLMProvider = LLMProvider.OLLAMA, **kwargs):
        # Store parallel_workers for this instance
        self.parallel_workers = kwargs.get('parallel_workers', 4)
        
        if provider == LLMProvider.OLLAMA:
            # Remove anthropic-specific parameters from kwargs before passing to OllamaClient
            client_kwargs = {k: v for k, v in kwargs.items() if k not in ['parallel_workers', 'anthropic_version', 'version_source']}
            self.client = OllamaClient(**client_kwargs)
        elif provider == LLMProvider.ANTHROPIC:
            api_key = kwargs.get('api_key')
            if not api_key:
                api_key = os.getenv('ANTHROPIC_API_KEY')
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY environment variable not set")
            # Remove parallel_workers from kwargs before passing to AnthropicClient
            client_kwargs = {k: v for k, v in kwargs.items() if k not in ['parallel_workers', 'api_key']}
            self.client = AnthropicClient(api_key=api_key, **client_kwargs)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
    
    async def _analyze_slice_async(self, slice_data, semaphore, results, lock):
        async with semaphore:
            analysis = await asyncio.to_thread(
                self.client.analyze_slice, slice_data["code"], slice_data.get("context", "")
            )
            try:
                parsed = json.loads(analysis)
            except json.JSONDecodeError:
                parsed = {
                    "vulnerability_type": "unknown",
                    "severity": "medium",
                    "description": analysis,
                    "suggested_fix": "Review code manually"
                }
            result = {**slice_data, "analysis": parsed, "raw_response": analysis}
            with lock:
                results.append(result)
                # If you update cost here, do it under the lock for thread safety

    def analyze_slices(self, slices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze multiple code slices."""
        # Use asyncio for parallel LLM calls
        semaphore = asyncio.Semaphore(self.parallel_workers)
        results = []
        lock = threading.Lock()
        async def runner():
            tasks = [
                self._analyze_slice_async(slice_data, semaphore, results, lock)
                for slice_data in slices
            ]
            await asyncio.gather(*tasks)
        asyncio.run(runner())
        return results
    
    def get_cost_estimate(self, slices: List[Dict[str, Any]]) -> float:
        """Estimate cost for analyzing slices."""
        slice_texts = [s["code"] for s in slices]
        return self.client.get_cost_estimate(slice_texts)
    
    def get_total_cost(self) -> float:
        """Get total cost so far."""
        return self.client.get_total_cost() 