"""
Configuration management for the AI Architecture Risk Auditor.
Loads settings from environment variables and .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Optional, Dict, Any, List
import os


class Neo4jSettings(BaseSettings):
    """Neo4j database settings."""
    model_config = SettingsConfigDict(env_prefix="NEO4J_", extra="ignore")
    
    uri: str = Field(default="bolt://localhost:7687")
    user: str = Field(default="neo4j")
    password: str = Field(default="password")
    timeout: int = 30


class OpenAISettings(BaseSettings):
    """OpenAI API settings."""
    model_config = SettingsConfigDict(env_prefix="OPENAI_", extra="ignore")
    
    api_key: Optional[str] = Field(default=None)
    model: str = Field(default="gpt-4o")
    temperature: float = Field(default=0.0)
    timeout: int = 60
    max_retries: int = 3
    enable_ai_layer: bool = Field(default=True)

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v):
        if not 0 <= v <= 2:
            raise ValueError("Temperature must be between 0 and 2")
        return v


class ScanSettings(BaseSettings):
    """Scanning and analysis settings."""
    model_config = SettingsConfigDict(env_prefix="SCAN_", extra="ignore")
    
    timeout_minutes: int = Field(default=10)
    max_workers: int = Field(default=4)
    enable_ast_cache: bool = Field(default=True)
    cache_dir: str = Field(default="./cache")


class SemgrepSettings(BaseSettings):
    """Semgrep configuration."""
    model_config = SettingsConfigDict(env_prefix="SEMGREP_", extra="ignore")
    
    config_url: str = Field(default="https://semgrep.dev/c/owasp-top-ten")
    timeout: int = Field(default=300)


class RiskThresholds(BaseSettings):
    """Risk detection thresholds."""
    model_config = SettingsConfigDict(extra="ignore")
    
    spof_fan_in_threshold: int = Field(default=2)
    boundary_crossing_threshold: int = Field(default=5)


class SecuritySettings(BaseSettings):
    """Security and privacy settings."""
    model_config = SettingsConfigDict(extra="ignore")
    
    redact_secrets_in_logs: bool = Field(default=True)
    redact_secrets_in_reports: bool = Field(default=True)
    secrets_hash_salt: str = Field(default="default-salt")


class LoggingSettings(BaseSettings):
    """Logging settings."""
    model_config = SettingsConfigDict(extra="ignore")
    
    level: str = Field(default="INFO")
    format: str = Field(default="json")


class Settings(BaseSettings):
    """Main application settings."""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    
    # Application
    app_name: str = "AI Architecture Risk Auditor"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    # Subsettings
    neo4j: Neo4jSettings = Neo4jSettings()
    openai: OpenAISettings = OpenAISettings()
    scan: ScanSettings = ScanSettings()
    semgrep: SemgrepSettings = SemgrepSettings()
    risk_thresholds: RiskThresholds = RiskThresholds()
    security: SecuritySettings = SecuritySettings()
    logging: LoggingSettings = LoggingSettings()
    
    # Supported languages
    supported_languages: List[str] = [
        "python",
        "javascript",
        "typescript",
        "java",
        "go",
    ]
    
    # Feature flags
    enable_ai_layer: bool = Field(default=True)
    enable_caching: bool = Field(default=True)

    @property
    def scan_timeout_seconds(self) -> int:
        return self.scan.timeout_minutes * 60


# Global settings instance
settings = Settings()
