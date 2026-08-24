"""Python-specific parser using tree-sitter."""
from typing import List, Dict, Any, Optional
import logging
from app.parser.base import LanguageParser

logger = logging.getLogger(__name__)


class PythonParser(LanguageParser):
    """Parser for Python code (FastAPI, Flask, Django, etc.)."""
    
    language_name = "python"
    file_extensions = [".py"]
    
    def __init__(self):
        try:
            from tree_sitter_python import language
            self.language = language()
            self.parser = None
        except ImportError:
            logger.warning("tree-sitter-python not installed, Python parsing may be limited")
            self.language = None
    
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Parse Python file and extract architectural information."""
        result = {
            "endpoints": [],
            "outbound_calls": [],
            "imports": [],
            "env_vars": [],
            "datastore_access": [],
            "config_refs": [],
            "errors": []
        }
        
        if not self.language:
            result["errors"].append("Python parser not available")
            return result
        
        try:
            # Parse with tree-sitter
            from tree_sitter import Parser
            parser = Parser()
            parser.set_language(self.language)
            
            tree = parser.parse(content.encode())
            
            result["endpoints"] = self.extract_endpoints(tree, content)
            result["outbound_calls"] = self.extract_outbound_calls(tree, content)
            result["imports"] = self.extract_imports(tree)
            result["env_vars"] = self.extract_env_vars(tree, content)
            result["auth_checks"] = self.extract_auth_checks(tree, content)
            
        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def extract_endpoints(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract FastAPI/Flask endpoints."""
        endpoints = []
        
        # Query for decorator patterns like @app.route, @router.post, etc.
        # This is a simplified implementation
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # FastAPI patterns
            if '@app.get' in line or '@app.post' in line or '@app.put' in line:
                method = 'GET' if '@app.get' in line else 'POST' if '@app.post' in line else 'PUT'
                # Extract path from parentheses
                if '(' in line and ')' in line:
                    start = line.index('(') + 1
                    end = line.index(')')
                    path = line[start:end].strip().strip('"\'')
                    endpoints.append({
                        "method": method,
                        "path": path,
                        "line": i + 1,
                        "handler": None,
                        "has_auth": self._has_auth_decorator(lines, i),
                    })
            
            # Flask patterns
            if '@app.route' in line or '@bp.route' in line:
                if '(' in line and ')' in line:
                    start = line.index('(') + 1
                    end = line.rindex(')')
                    route_def = line[start:end]
                    
                    # Extract path
                    if ',' in route_def:
                        path = route_def.split(',')[0].strip().strip('"\'')
                    else:
                        path = route_def.strip().strip('"\'')
                    
                    # Extract methods
                    methods = ['GET']  # Default
                    if 'methods=' in route_def:
                        methods_str = route_def.split('methods=')[1].strip()
                        # Simple extraction
                        if 'POST' in methods_str:
                            methods.append('POST')
                    
                    for method in methods:
                        endpoints.append({
                            "method": method,
                            "path": path,
                            "line": i + 1,
                            "handler": None,
                            "has_auth": self._has_auth_decorator(lines, i),
                        })
        
        return endpoints
    
    def extract_outbound_calls(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract outbound HTTP/DB/queue calls."""
        calls = []
        lines = content.split('\n')
        
        # HTTP client patterns
        http_patterns = [
            ('requests.get', 'GET'),
            ('requests.post', 'POST'),
            ('requests.put', 'PUT'),
            ('requests.delete', 'DELETE'),
            ('httpx.get', 'GET'),
            ('httpx.post', 'POST'),
            ('aiohttp', 'HTTP'),
            ('urllib.request', 'HTTP'),
        ]
        
        for i, line in enumerate(lines):
            for pattern, method in http_patterns:
                if pattern in line:
                    calls.append({
                        "type": "http",
                        "method": method,
                        "line": i + 1,
                        "target_url": None,  # Would need deeper parsing
                        "is_encrypted": 'https' in line.lower(),
                    })
            
            # Database patterns
            if 'sql.execute' in line or 'db.query' in line or 'cursor.execute' in line:
                calls.append({
                    "type": "database",
                    "line": i + 1,
                    "operation": "query",
                })
            
            # Message queue patterns
            if 'producer.send' in line or 'publisher.publish' in line:
                calls.append({
                    "type": "queue",
                    "line": i + 1,
                })
        
        return calls
    
    def extract_imports(self, tree: Any) -> List[str]:
        """Extract imports."""
        imports = []
        # Would traverse AST in full implementation
        return imports
    
    def extract_env_vars(self, tree: Any, content: str) -> List[str]:
        """Extract environment variable references."""
        env_vars = []
        lines = content.split('\n')
        
        for line in lines:
            if 'os.getenv' in line or 'os.environ' in line:
                # Extract var name
                if 'os.getenv(' in line:
                    start = line.index('os.getenv(') + 10
                    end = line.index(')', start)
                    var_ref = line[start:end].strip().strip('"\'')
                    env_vars.append(var_ref)
        
        return env_vars
    
    def extract_auth_checks(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract authentication decorators/middleware."""
        auth_checks = []
        lines = content.split('\n')
        
        auth_patterns = [
            'require_auth',
            'jwt_required',
            'login_required',
            'permission_required',
            'oauth2_scheme',
        ]
        
        for i, line in enumerate(lines):
            for pattern in auth_patterns:
                if pattern in line.lower():
                    auth_checks.append({
                        "type": "decorator",
                        "pattern": pattern,
                        "line": i + 1,
                    })
        
        return auth_checks
    
    def _has_auth_decorator(self, lines: List[str], endpoint_line: int) -> bool:
        """Check if endpoint has auth decorator above it."""
        # Check lines above the endpoint definition
        for i in range(max(0, endpoint_line - 5), endpoint_line):
            line = lines[i].lower()
            if any(auth in line for auth in ['require_auth', 'jwt_required', 'login_required', 'oauth']):
                return True
        return False
