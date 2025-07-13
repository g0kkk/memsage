"""Tests for Anthropic LLM support."""

import pytest
import os
from unittest.mock import Mock, patch
from memsage.llm import LLMAnalyzer, LLMProvider, AnthropicClient
from memsage.config import ConfigManager


class TestAnthropicSupport:
    """Test Anthropic LLM integration."""
    
    def test_anthropic_client_initialization(self):
        """Test AnthropicClient initialization with API key."""
        api_key = "test-api-key"
        model = "claude-3-haiku-20240307"
        
        with patch('memsage.llm.anthropic') as mock_anthropic:
            mock_client = Mock()
            mock_anthropic.Anthropic.return_value = mock_client
            
            client = AnthropicClient(api_key=api_key, model=model)
            
            assert client.api_key == api_key
            assert client.model == model
            mock_anthropic.Anthropic.assert_called_once_with(api_key=api_key)
    
    def test_anthropic_client_missing_api_key(self):
        """Test that AnthropicClient raises error without API key."""
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY environment variable not set"):
            LLMAnalyzer(provider=LLMProvider.ANTHROPIC)
    
    def test_anthropic_client_with_env_api_key(self):
        """Test AnthropicClient initialization with environment API key."""
        api_key = "test-env-api-key"
        
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': api_key}):
            with patch('memsage.llm.anthropic') as mock_anthropic:
                mock_client = Mock()
                mock_anthropic.Anthropic.return_value = mock_client
                
                analyzer = LLMAnalyzer(provider=LLMProvider.ANTHROPIC, model="claude-3-haiku-20240307")
                
                assert analyzer.client.api_key == api_key
                mock_anthropic.Anthropic.assert_called_once_with(api_key=api_key)
    
    def test_anthropic_cost_calculation(self):
        """Test Anthropic cost calculation for different models."""
        api_key = "test-api-key"
        
        with patch('memsage.llm.anthropic') as mock_anthropic:
            mock_client = Mock()
            mock_anthropic.Anthropic.return_value = mock_client
            
            # Test Haiku pricing
            client = AnthropicClient(api_key=api_key, model="claude-3-haiku-20240307")
            cost = client._calculate_cost(1000, 500)  # 1k input, 500 output tokens
            expected_cost = (1000 / 1_000_000) * 0.25 + (500 / 1_000_000) * 1.25
            assert abs(cost - expected_cost) < 0.0001
            
            # Test Sonnet pricing
            client = AnthropicClient(api_key=api_key, model="claude-3-sonnet-20240229")
            cost = client._calculate_cost(1000, 500)
            expected_cost = (1000 / 1_000_000) * 3.0 + (500 / 1_000_000) * 15.0
            assert abs(cost - expected_cost) < 0.0001
    
    def test_anthropic_analyze_slice(self):
        """Test Anthropic slice analysis."""
        api_key = "test-api-key"
        code_slice = "char buffer[10]; strcpy(buffer, argv[1]);"
        
        with patch('memsage.llm.anthropic') as mock_anthropic:
            mock_client = Mock()
            mock_anthropic.Anthropic.return_value = mock_client
            
            # Mock the API response
            mock_response = Mock()
            mock_response.content = [Mock(text='{"vulnerability_type": "buffer_overflow", "severity": "high", "description": "Buffer overflow detected", "suggested_fix": "Use strncpy"}')]
            mock_response.usage.input_tokens = 100
            mock_response.usage.output_tokens = 50
            
            mock_client.messages.create.return_value = mock_response
            
            client = AnthropicClient(api_key=api_key, model="claude-3-haiku-20240307")
            result = client.analyze_slice(code_slice)
            
            # Verify API call was made correctly
            mock_client.messages.create.assert_called_once()
            call_args = mock_client.messages.create.call_args
            assert call_args[1]['model'] == "claude-3-haiku-20240307"
            assert call_args[1]['max_tokens'] == 500
            assert call_args[1]['temperature'] == 0.1
            
            # Verify result contains expected content
            assert "buffer_overflow" in result
            assert "high" in result
    
    def test_config_llm_provider_environment(self):
        """Test that LLM_PROVIDER environment variable is respected."""
        with patch.dict(os.environ, {'LLM_PROVIDER': 'anthropic'}):
            config_manager = ConfigManager()
            config = config_manager.get_config()
            assert config.llm_provider == "anthropic"
    
    def test_config_llm_provider_fallback(self):
        """Test that MEMSAGE_LLM_PROVIDER is used as fallback."""
        with patch.dict(os.environ, {'MEMSAGE_LLM_PROVIDER': 'anthropic'}):
            config_manager = ConfigManager()
            config = config_manager.get_config()
            assert config.llm_provider == "anthropic"
    
    def test_ollama_remains_default(self):
        """Test that Ollama remains the default provider."""
        # Clear any environment variables
        with patch.dict(os.environ, {}, clear=True):
            config_manager = ConfigManager()
            config = config_manager.get_config()
            assert config.llm_provider == "ollama" 