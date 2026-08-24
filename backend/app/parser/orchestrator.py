"""Multi-language parser orchestration."""
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path
from app.parser.base import LanguageParser
from app.parser.python_parser import PythonParser
from app.parser.js_parser import JavaScriptParser

logger = logging.getLogger(__name__)


class ParserFactory:
    """Factory for language-specific parsers."""
    
    _parsers: Dict[str, LanguageParser] = {}
    
    @classmethod
    def get_parser(cls, language: str) -> Optional[LanguageParser]:
        """Get or create a parser for the specified language."""
        if language in cls._parsers:
            return cls._parsers[language]
        
        if language == "python":
            parser = PythonParser()
        elif language in ["javascript", "typescript"]:
            parser = JavaScriptParser()
        else:
            logger.warning(f"No parser available for language: {language}")
            return None
        
        cls._parsers[language] = parser
        return parser
    
    @classmethod
    def detect_language(cls, file_path: str) -> Optional[str]:
        """Detect language from file extension."""
        extension = Path(file_path).suffix.lower()
        
        language_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
        }
        
        return language_map.get(extension)


class MultiLanguageParser:
    """Orchestrator for parsing multiple languages."""
    
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Parse a file, auto-detecting its language.
        
        Args:
            file_path: Path to file
            content: File contents
            
        Returns:
            Parsed architectural information
        """
        language = ParserFactory.detect_language(file_path)
        
        if not language:
            logger.warning(f"Could not detect language for {file_path}")
            return {
                "endpoints": [],
                "outbound_calls": [],
                "imports": [],
                "env_vars": [],
                "datastore_access": [],
                "config_refs": [],
                "errors": [f"Unsupported language: {file_path}"]
            }
        
        parser = ParserFactory.get_parser(language)
        if not parser:
            return {
                "endpoints": [],
                "outbound_calls": [],
                "imports": [],
                "env_vars": [],
                "datastore_access": [],
                "config_refs": [],
                "errors": [f"No parser for language: {language}"]
            }
        
        return parser.parse_file(file_path, content)
    
    def parse_directory(
        self,
        directory: str,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Parse all supported files in a directory.
        
        Args:
            directory: Root directory to scan
            include_patterns: Patterns to include
            exclude_patterns: Patterns to exclude
            
        Returns:
            Dictionary mapping file paths to parsed data
        """
        from pathlib import Path
        import fnmatch
        
        include_patterns = include_patterns or ["**/*.py", "**/*.js", "**/*.ts", "**/*.java", "**/*.go"]
        exclude_patterns = exclude_patterns or ["node_modules/**", "vendor/**", "dist/**", "build/**"]
        
        results = {}
        root = Path(directory)
        
        for pattern in include_patterns:
            for file_path in root.glob(pattern):
                # Check exclude patterns
                file_str = str(file_path)
                if any(fnmatch.fnmatch(file_str, ex) for ex in exclude_patterns):
                    continue
                
                if file_path.is_file():
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        rel_path = str(file_path.relative_to(root))
                        results[rel_path] = self.parse_file(str(file_path), content)
                    except Exception as e:
                        logger.error(f"Error parsing {file_path}: {e}")
                        results[str(file_path)] = {"errors": [str(e)]}
        
        return results
