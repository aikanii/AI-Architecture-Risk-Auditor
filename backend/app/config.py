"""
Configuration management for the AI Architecture Risk Auditor.
Loads settings from environment variables and .env file.
"""
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Optional, Dict, Any
import os


class Neo4jSettings(BaseSettings):
    """Neo4j database settings."""
    uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    user: str = Field(default="neo4j", env="NEO4J_USER")
    password: str = Field(default="password", env="NEO4J_PASSWORD")
    timeout: int = 30
    
    class Config:
        env_prefix = "NEO4J_"


class OpenAISettings(BaseSettings):
    """OpenAI API settings."""
    api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    model: str = Field(default="gpt-4o", env="OPENAI_MODEL")
    temperature: float = Field(default=0.0, env="OPENAI_TEMPERATURE")
    timeout: int = 60
    max_retries: int = 3
    enable_ai_layer: bool = Field(default=True)

    @validator("temperature")
    def validate_temperature(cls, v):
        if not 0 <= v <= 2:
            raise ValueError("Temperature must be between 0 and 2")
        return v

    class Config:
        env_prefix = "OPENAI_"


class ScanSettings(BaseSettings):
    """Scanning and analysis settings."""
    timeout_minutes: int = Field(default=10, env="SCAN_TIMEOUT_MINUTES")
    max_workers: int = Field(default=4, env="MAX_WORKERS")
    enable_ast_cache: bool = Field(default=True, env="ENABLE_AST_CACHE")
    cache_dir: str = Field(default="./cache", env="CACHE_DIR")
    
    class Config:
        env_prefix = "SCAN_"


class SemgrepSettings(BaseSettings):
    """Semgrep configuration."""
    config_url: str = Field(
        default="https://semgrep.dev/c/owasp-top-ten",
        env="SEMGREP_CONFIG_URL"
    )
    timeout: int = Field(default=300, env="SEMGREP_TIMEOUT")
    
    class Config:
        env_prefix = "SEMGREP_"


class RiskThresholds(BaseSettings):
    """Risk detection thresholds."""
    spof_fan_in_threshold: int = Field(default=3, env="SPOF_FAN_IN_THRESHOLD")
    boundary_crossing_threshold: int = Field(default=5, env="BOUNDARY_CROSSING_THRESHOLD")
    
    class Config:
        env_prefix = ""


class SecuritySettings(BaseSettings):
    """Security and privacy settings."""
    redact_secrets_in_logs: bool = Field(default=True, env="REDACT_SECRETS_IN_LOGS")
    redact_secrets_in_reports: bool = Field(default=True, env="REDACT_SECRETS_IN_REPORTS")
    secrets_hash_salt: str = Field(default="default-salt", env="SECRETS_HASH_SALT")
    
    class Config:
        env_prefix = ""


class Settings(BaseSettings):
    """Main application settings."""
    # Application
    app_name: str = "AI Architecture Risk Auditor"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # Subsettings
    neo4j: Neo4jSettings = Neo4jSettings()
    openai: OpenAISettings = OpenAISettings()
    scan: ScanSettings = ScanSettings()
    semgrep: SemgrepSettings = SemgrepSettings()
    risk_thresholds: RiskThresholds = RiskThresholds()
    security: SecuritySettings = SecuritySettings()
    
    # Supported languages
    supported_languages: list = [
        "python",
        "javascript",
        "typescript",
        "java",
        "go",
    ]
    
    # Feature flags
    enable_ai_layer: bool = Field(default=True, env="ENABLE_AI_LAYER")
    enable_caching: bool = Field(default=True)
    
    class Config:
        env_file = ".env"
        case_sensitive = False

    @property
    def scan_timeout_seconds(self) -> int:
        return self.scan.timeout_minutes * 60


# Global settings instance
settings = Settings()
