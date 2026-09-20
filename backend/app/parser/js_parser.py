"""JavaScript/TypeScript-specific parser."""
from typing import List, Dict, Any, Optional
import logging
import re
from pathlib import Path
from app.parser.base import LanguageParser

logger = logging.getLogger(__name__)


class JavaScriptParser(LanguageParser):
    """Parser for JavaScript/TypeScript (Express, NestJS, Next.js, etc.)."""
    
    language_name = "javascript"
    file_extensions = [".js", ".ts", ".jsx", ".tsx", "js", "ts", "jsx", "tsx"]
    
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Parse JavaScript/TypeScript file."""
        result = {
            "endpoints": [],
            "outbound_calls": [],
            "imports": [],
            "env_vars": [],
            "datastore_access": [],
            "config_refs": [],
            "auth_checks": [],
            "secrets": [],
            "errors": []
        }
        
        try:
            result["endpoints"] = self.extract_endpoints(None, content)
            result["outbound_calls"] = self.extract_outbound_calls(None, content)
            result["imports"] = self.extract_imports(None, content)
            result["env_vars"] = self.extract_env_vars(None, content)
            result["auth_checks"] = self.extract_auth_checks(None, content)
            result["datastore_access"] = self.extract_datastore_access(content)
            result["secrets"] = self.extract_secrets(content)
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
            'app.patch': 'PATCH',
            'router.get': 'GET',
            'router.post': 'POST',
            'router.put': 'PUT',
            'router.delete': 'DELETE',
            'router.patch': 'PATCH',
        }
        
        for i, line in enumerate(lines):
            for pattern, method in express_patterns.items():
                if pattern in line:
                    match = re.search(rf"{re.escape(pattern)}\(['\"]([^'\"]+)['\"]", line)
                    if match:
                        path = match.group(1)
                        has_auth = self._has_auth_middleware(lines, i)
                        endpoints.append({
                            "method": method,
                            "path": path,
                            "line": i + 1,
                            "has_auth": has_auth,
                            "is_public": not has_auth,
                            "rate_limit_enabled": any(rl in lines[max(0, i-3):i+2] for rl in ['rateLimit', 'throttle']),
                        })
            
            # NestJS decorators
            nest_match = re.search(r'@(Get|Post|Put|Delete|Patch)\([\'"]([^\'"]*)[\'"]\)', line)
            if nest_match:
                method = nest_match.group(1).upper()
                path = nest_match.group(2) or "/"
                has_auth = self._has_auth_middleware(lines, i)
                endpoints.append({
                    "method": method,
                    "path": path,
                    "line": i + 1,
                    "has_auth": has_auth,
                    "is_public": not has_auth,
                    "rate_limit_enabled": False,
                })
        
        return endpoints
    
    def extract_outbound_calls(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract outbound calls."""
        calls = []
        lines = content.split('\n')
        
        http_patterns = [
            ('axios.get', 'GET'),
            ('axios.post', 'POST'),
            ('axios.put', 'PUT'),
            ('axios.delete', 'DELETE'),
            ('fetch(', 'FETCH'),
            ('http.get', 'GET'),
            ('http.post', 'POST'),
            ('request.get', 'GET'),
            ('request.post', 'POST'),
        ]
        
        for i, line in enumerate(lines):
            for pattern, method in http_patterns:
                if pattern in line:
                    target_url_match = re.search(rf"{re.escape(pattern)}\([`'\"]([^`'\"]+)[`'\"]", line)
                    target_url = target_url_match.group(1) if target_url_match else ""
                    is_encrypted = target_url.startswith("https://") if target_url else "https" in line.lower()
                    
                    callee_service = None
                    service_url_match = re.search(r'https?://([a-zA-Z0-9_\-]+)(?::\d+)?', target_url)
                    if service_url_match:
                        callee_service = service_url_match.group(1).replace('-', '_')
                    
                    calls.append({
                        "type": "http",
                        "method": method,
                        "line": i + 1,
                        "target_url": target_url,
                        "callee_service": callee_service,
                        "is_encrypted": is_encrypted,
                    })
            
            # Database calls
            if any(p in line for p in ['db.query', 'client.query', 'knex(', 'prisma.', 'mongoose.']):
                calls.append({
                    "type": "database",
                    "line": i + 1,
                    "operation": "write" if any(w in line.upper() for w in ['INSERT', 'UPDATE', 'DELETE', 'CREATE']) else "query",
                })
            
            # Message queue
            if any(p in line for p in ['producer.send', 'client.publish', 'amqp.', 'channel.sendToQueue']):
                calls.append({
                    "type": "queue",
                    "line": i + 1,
                })
        
        return calls
    
    def extract_imports(self, tree: Any, content: Optional[str] = None) -> List[str]:
        """Extract imports."""
        imports = []
        if content:
            for line in content.split('\n'):
                line_s = line.strip()
                if line_s.startswith(('import ', 'const ', 'let ', 'var ')) and ('require(' in line_s or ' from ' in line_s):
                    imports.append(line_s)
        return imports
    
    def extract_env_vars(self, tree: Any, content: str) -> List[str]:
        """Extract environment variables."""
        env_vars = []
        matches = re.findall(r'process\.env\.([a-zA-Z0-9_]+)', content)
        for m in matches:
            if m not in env_vars:
                env_vars.append(m)
        return env_vars
    
    def extract_auth_checks(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract auth decorators/middleware."""
        auth_checks = []
        lines = content.split('\n')
        
        auth_patterns = [
            'useguards',
            'requireauth',
            'auth.required',
            'authenticate',
            'jwt',
            'passport',
        ]
        
        for i, line in enumerate(lines):
            for pattern in auth_patterns:
                if pattern in line.lower():
                    auth_checks.append({
                        "type": "middleware" if 'use' in line.lower() else "decorator",
                        "pattern": pattern,
                        "line": i + 1,
                    })
                    break
        
        return auth_checks

    def extract_datastore_access(self, content: str) -> List[Dict[str, Any]]:
        """Extract database access patterns."""
        datastores = []
        db_urls = re.findall(r'(?:DATABASE_URL|MONGODB_URI|POSTGRES_URL)\s*[:=]\s*["\']([^"\']+)["\']', content)
        for url in db_urls:
            datastores.append({
                "connection_url": url,
                "name": "db",
                "type": "sql" if "postgres" in url or "mysql" in url else "nosql",
                "has_writes": True,
                "has_reads": True,
            })
        return datastores

    def extract_secrets(self, content: str) -> List[Dict[str, Any]]:
        """Extract hardcoded secrets in JS/TS."""
        secrets = []
        lines = content.split('\n')
        for i, line in enumerate(lines):
            match = re.search(r'(?:const|let|var)?\s*([a-zA-Z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN))\s*=\s*["\']([^"\']+)["\']', line)
            if match and len(match.group(2)) >= 6 and not match.group(2).startswith("process."):
                secrets.append({
                    "name": match.group(1),
                    "line": i + 1,
                    "value": match.group(2),
                })
        return secrets
    
    def _has_auth_middleware(self, lines: List[str], endpoint_line: int) -> bool:
        """Check if endpoint has auth middleware."""
        for i in range(max(0, endpoint_line - 5), endpoint_line):
            line = lines[i].lower()
            if any(auth in line for auth in ['authenticate', 'jwt', 'useguards', 'requireauth', 'isauthenticated']):
                return True
        return False
