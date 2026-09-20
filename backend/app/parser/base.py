"""
Tree-sitter integration for multi-language AST parsing.
Provides language-specific extraction of services, endpoints, calls, etc.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class LanguageParser(ABC):
    """
    Abstract base class for language-specific parsers.
    Each language implementation handles AST extraction specific to that language.
    """
    
    language_name: str
    file_extensions: List[str]
    
    def supports(self, file_path: str) -> bool:
        """Check if this parser supports the given file extension."""
        ext = Path(file_path).suffix.lower()
        ext_no_dot = ext.lstrip(".")
        return ext in self.file_extensions or ext_no_dot in self.file_extensions
    
    @abstractmethod
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Parse a file and extract architectural information.
        
        Args:
            file_path: Path to file being parsed
            content: File contents
            
        Returns:
            Dictionary with extracted data:
            {
                "endpoints": [...],
                "outbound_calls": [...],
                "imports": [...],
                "env_vars": [...],
                "datastore_access": [...],
                "config_refs": [...],
                "errors": [...]
            }
        """
        pass
    
    @abstractmethod
    def extract_endpoints(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract HTTP endpoints from AST."""
        pass
    
    @abstractmethod
    def extract_outbound_calls(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract outbound calls (HTTP, DB, queue, etc.)."""
        pass
    
    @abstractmethod
    def extract_imports(self, tree: Any) -> List[str]:
        """Extract import/dependency statements."""
        pass
    
    @abstractmethod
    def extract_env_vars(self, tree: Any, content: str) -> List[str]:
        """Extract environment variable references."""
        pass
    
    @abstractmethod
    def extract_auth_checks(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract authentication middleware/decorators."""
        pass
