"""JavaScript/TypeScript-specific parser."""
from typing import List, Dict, Any
import logging
import re
from app.parser.base import LanguageParser

logger = logging.getLogger(__name__)


class JavaScriptParser(LanguageParser):
    """Parser for JavaScript/TypeScript (Express, NestJS, etc.)."""
    
    language_name = "javascript"
    file_extensions = [".js", ".ts", ".jsx", ".tsx"]
    
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Parse JavaScript/TypeScript file."""
        result = {
            "endpoints": [],
            "outbound_calls": [],
            "imports": [],
            "env_vars": [],
            "datastore_access": [],
            "config_refs": [],
            "errors": []
        }
        
        try:
            result["endpoints"] = self.extract_endpoints(None, content)
            result["outbound_calls"] = self.extract_outbound_calls(None, content)
            result["imports"] = self.extract_imports(None)
            result["env_vars"] = self.extract_env_vars(None, content)
            result["auth_checks"] = self.extract_auth_checks(None, content)
        except Exception as e:
            logger.error(f"Error parsing JS file {file_path}: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def extract_endpoints(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract Express/NestJS endpoints."""
        endpoints = []
        lines = content.split('\n')
        
        # Express patterns
        express_patterns = {
            'app.get': 'GET',
            'app.post': 'POST',
            'app.put': 'PUT',
            'app.delete': 'DELETE',
            'router.get': 'GET',
            'router.post': 'POST',
            'router.put': 'PUT',
            'router.delete': 'DELETE',
        }
        
        for i, line in enumerate(lines):
            for pattern, method in express_patterns.items():
                if pattern in line:
                    # Extract path
                    match = re.search(rf"{pattern}\(['\"]([^'\"]+)['\"]", line)
                    if match:
                        path = match.group(1)
                        endpoints.append({
                            "method": method,
                            "path": path,
                            "line": i + 1,
                            "has_auth": self._has_auth_middleware(lines, i),
                        })
            
            # NestJS decorators
            if '@Get(' in line or '@Post(' in line:
                method = 'GET' if '@Get' in line else 'POST'
                match = re.search(r'@\w+\([\'"]([^\'"]*)[\'"]', line)
                if match:
                    path = match.group(1)
                    endpoints.append({
                        "method": method,
                        "path": path,
                        "line": i + 1,
                        "has_auth": self._has_auth_middleware(lines, i),
                    })
        
        return endpoints
    
    def extract_outbound_calls(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract outbound calls."""
        calls = []
        lines = content.split('\n')
        
        http_patterns = [
            'axios.get',
            'axios.post',
            'fetch(',
            'http.get',
            'http.post',
            'request.get',
            'request.post',
        ]
        
        for i, line in enumerate(lines):
            for pattern in http_patterns:
                if pattern in line:
                    method = 'GET' if 'get' in pattern.lower() else 'POST' if 'post' in pattern.lower() else 'HTTP'
                    calls.append({
                        "type": "http",
                        "method": method,
                        "line": i + 1,
                        "is_encrypted": 'https' in line.lower(),
                    })
            
            # Database calls
            if 'db.query' in line or 'client.query' in line or 'execute(' in line:
                calls.append({
                    "type": "database",
                    "line": i + 1,
                })
            
            # Message queue
            if 'producer.send' in line or 'client.publish' in line:
                calls.append({
                    "type": "queue",
                    "line": i + 1,
                })
        
        return calls
    
    def extract_imports(self, tree: Any) -> List[str]:
        """Extract imports."""
        return []
    
    def extract_env_vars(self, tree: Any, content: str) -> List[str]:
        """Extract environment variables."""
        env_vars = []
        lines = content.split('\n')
        
        for line in lines:
            if 'process.env' in line:
                # Extract var name
                match = re.search(r'process\.env\.(\w+)', line)
                if match:
                    env_vars.append(match.group(1))
        
        return env_vars
    
    def extract_auth_checks(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract auth decorators/middleware."""
        auth_checks = []
        lines = content.split('\n')
        
        auth_patterns = [
            'UseGuards',
            'RequireAuth',
            'auth.required',
            'authenticate',
            'jwt',
        ]
        
        for i, line in enumerate(lines):
            for pattern in auth_patterns:
                if pattern in line:
                    auth_checks.append({
                        "type": "middleware" if 'use' in line.lower() else "decorator",
                        "pattern": pattern,
                        "line": i + 1,
                    })
        
        return auth_checks
    
    def _has_auth_middleware(self, lines: List[str], endpoint_line: int) -> bool:
        """Check if endpoint has auth middleware."""
        for i in range(max(0, endpoint_line - 5), endpoint_line):
            line = lines[i].lower()
            if any(auth in line for auth in ['authenticate', 'jwt', 'useguards', 'requireauth']):
                return True
        return False
