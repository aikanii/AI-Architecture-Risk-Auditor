"""Python-specific parser using tree-sitter and standard library AST."""
from typing import List, Dict, Any, Optional
import logging
import ast
import re
from pathlib import Path
from app.parser.base import LanguageParser

logger = logging.getLogger(__name__)


class PythonParser(LanguageParser):
    """Parser for Python code (FastAPI, Flask, Django, etc.)."""
    
    language_name = "python"
    file_extensions = [".py", "py"]
    
    def __init__(self):
        self.language = None
        try:
            import tree_sitter_python as tspython
            from tree_sitter import Language
            self.language = Language(tspython.language())
        except Exception:
            logger.debug("tree-sitter-python not installed or failed to initialize, using AST fallback")
    
    def parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """Parse Python file and extract architectural information."""
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
        
        tree = None
        if self.language:
            try:
                from tree_sitter import Parser
                parser = Parser(self.language)
                tree = parser.parse(content.encode())
            except Exception:
                try:
                    from tree_sitter import Parser
                    parser = Parser()
                    parser.language = self.language
                    tree = parser.parse(content.encode())
                except Exception:
                    tree = None
        
        # Extract endpoints, calls, etc. via combined AST and pattern analysis
        try:
            result["endpoints"] = self.extract_endpoints(tree, content)
            result["outbound_calls"] = self.extract_outbound_calls(tree, content)
            result["imports"] = self.extract_imports(tree, content)
            result["env_vars"] = self.extract_env_vars(tree, content)
            result["auth_checks"] = self.extract_auth_checks(tree, content)
            result["datastore_access"] = self.extract_datastore_access(tree, content)
            result["secrets"] = self.extract_secrets(content)
        except Exception as e:
            logger.error(f"Error parsing Python file {file_path}: {e}")
            result["errors"].append(str(e))
        
        return result
    
    def extract_endpoints(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract FastAPI/Flask endpoints."""
        endpoints = []
        lines = content.split('\n')
        
        # Try AST-based parsing first for accuracy
        try:
            parsed_ast = ast.parse(content)
            for node in ast.walk(parsed_ast):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        ep = self._extract_endpoint_from_decorator(decorator, node, lines)
                        if ep:
                            endpoints.append(ep)
        except Exception:
            pass

        # If AST didn't find any or failed, fallback to line-based regex
        if not endpoints:
            for i, line in enumerate(lines):
                fastapi_match = re.search(r'@(?:app|router|bp)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', line, re.IGNORECASE)
                if fastapi_match:
                    method = fastapi_match.group(1).upper()
                    path = fastapi_match.group(2)
                    has_auth = self._has_auth_decorator(lines, i)
                    endpoints.append({
                        "method": method,
                        "path": path,
                        "line": i + 1,
                        "handler": None,
                        "has_auth": has_auth,
                        "is_public": not has_auth,
                        "rate_limit_enabled": self._has_rate_limit(lines, i),
                    })
                
                flask_match = re.search(r'@(?:app|bp)\.route\(\s*["\']([^"\']+)["\'](?:,\s*methods=\[([^\]]+)\])?', line, re.IGNORECASE)
                if flask_match:
                    path = flask_match.group(1)
                    methods_str = flask_match.group(2) or "'GET'"
                    methods = [m.strip().strip("'\"").upper() for m in methods_str.split(',') if m.strip()]
                    has_auth = self._has_auth_decorator(lines, i)
                    for method in methods:
                        endpoints.append({
                            "method": method,
                            "path": path,
                            "line": i + 1,
                            "handler": None,
                            "has_auth": has_auth,
                            "is_public": not has_auth,
                            "rate_limit_enabled": self._has_rate_limit(lines, i),
                        })
        
        return endpoints
    
    def _extract_endpoint_from_decorator(self, decorator: ast.AST, func_node: ast.AST, lines: List[str]) -> Optional[Dict[str, Any]]:
        """Extract endpoint details from an AST decorator."""
        if not isinstance(decorator, ast.Call):
            return None
        
        method = None
        path = None
        
        # Check for @app.get('/path') or @router.post('/path')
        if isinstance(decorator.func, ast.Attribute):
            attr_name = decorator.func.attr.upper()
            if attr_name in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                method = attr_name
            elif attr_name == 'ROUTE':
                method = 'GET'
                # Check methods argument
                for kw in decorator.keywords:
                    if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                method = elt.value.upper()
                                break
        
        if method and decorator.args:
            first_arg = decorator.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                path = first_arg.value
        
        if method and path:
            line_no = getattr(func_node, 'lineno', 1)
            has_auth = self._has_auth_ast(func_node) or self._has_auth_decorator(lines, line_no - 1)
            return {
                "method": method,
                "path": path,
                "line": line_no,
                "handler": getattr(func_node, 'name', None),
                "has_auth": has_auth,
                "is_public": not has_auth,
                "rate_limit_enabled": self._has_rate_limit(lines, line_no - 1),
            }
        return None
    
    def _has_auth_ast(self, func_node: ast.AST) -> bool:
        """Check if function parameters have auth dependencies (e.g. Depends(verify_token))."""
        for default in getattr(func_node.args, 'defaults', []):
            if isinstance(default, ast.Call):
                func_name = ""
                if isinstance(default.func, ast.Name):
                    func_name = default.func.id
                elif isinstance(default.func, ast.Attribute):
                    func_name = default.func.attr
                if func_name in ['Depends', 'Security']:
                    for d_arg in default.args:
                        d_name = getattr(d_arg, 'id', getattr(d_arg, 'attr', ''))
                        if any(token in d_name.lower() for token in ['auth', 'token', 'verify', 'jwt', 'user', 'perm']):
                            return True
        return False
    
    def _has_rate_limit(self, lines: List[str], line_idx: int) -> bool:
        """Check if rate limit decorator is present."""
        for i in range(max(0, line_idx - 5), min(len(lines), line_idx + 2)):
            if any(rl in lines[i].lower() for rl in ['rate_limit', 'limiter.limit', 'throttle']):
                return True
        return False
    
    def extract_outbound_calls(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract outbound HTTP/DB/queue calls."""
        calls = []
        lines = content.split('\n')
        
        # Build variable dictionary for URL variable resolution
        var_defs = {}
        try:
            parsed_ast = ast.parse(content)
            for node in parsed_ast.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                            var_defs[target.id] = str(node.value.value)
        except Exception:
            pass

        # Regex fallback for variable definitions
        for line in lines:
            m = re.match(r'([A-Z0-9_]+)\s*=\s*["\']([^"\']+)["\']', line.strip())
            if m:
                var_defs[m.group(1)] = m.group(2)

        # Parse AST calls
        try:
            parsed_ast = ast.parse(content)
            for node in ast.walk(parsed_ast):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    attr = node.func.attr.lower()
                    if attr in ['get', 'post', 'put', 'delete', 'patch']:
                        target_url = ""
                        if node.args:
                            arg0 = node.args[0]
                            if isinstance(arg0, ast.Constant):
                                target_url = str(arg0.value)
                            elif isinstance(arg0, ast.Name) and arg0.id in var_defs:
                                target_url = var_defs[arg0.id]
                            elif isinstance(arg0, ast.JoinedStr):
                                parts = []
                                for val in arg0.values:
                                    if isinstance(val, ast.Constant):
                                        parts.append(str(val.value))
                                    elif isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                                        parts.append(var_defs.get(val.value.id, val.value.id))
                                target_url = "".join(parts)
                        
                        # Only keep if looks like HTTP call
                        if target_url or isinstance(node.func.value, ast.Name) and node.func.value.id in ['client', 'httpx', 'requests', 'session']:
                            line_no = getattr(node, 'lineno', 1)
                            is_encrypted = target_url.startswith("https://")
                            
                            callee_service = None
                            service_match = re.search(r'https?://([a-zA-Z0-9_\-]+)(?::\d+)?', target_url)
                            if service_match:
                                callee_service = service_match.group(1).replace('-', '_')
                            
                            has_timeout = any(kw.arg == 'timeout' and not (isinstance(kw.value, ast.Constant) and kw.value.value is None) for kw in node.keywords)
                            
                            calls.append({
                                "type": "http",
                                "method": attr.upper(),
                                "line": line_no,
                                "target_url": target_url,
                                "callee_service": callee_service,
                                "is_encrypted": is_encrypted,
                                "is_synchronous": True,
                                "has_timeout": has_timeout,
                                "has_circuit_breaker": False,
                            })
        except Exception:
            pass
        
        # Extract DB and Queue calls line-by-line
        for i, line in enumerate(lines):
            if any(p in line for p in ['database.fetch', 'database.execute', 'cursor.execute', 'db.query', 'sql.execute']):
                is_write = any(w in line.upper() for w in ['INSERT', 'UPDATE', 'DELETE', 'EXECUTE'])
                calls.append({
                    "type": "database",
                    "line": i + 1,
                    "operation": "write" if is_write else "query",
                })
            
            if any(p in line for p in ['producer.send', 'publisher.publish', 'queue.put', 'channel.basic_publish']):
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
                if line_s.startswith(('import ', 'from ')):
                    imports.append(line_s)
        return imports
    
    def extract_env_vars(self, tree: Any, content: str) -> List[str]:
        """Extract environment variable references."""
        env_vars = []
        matches = re.findall(r'os\.(?:getenv|environ(?:\.get)?)\s*[\(\[]\s*["\']([a-zA-Z0-9_]+)["\']', content)
        for m in matches:
            if m not in env_vars:
                env_vars.append(m)
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
            'verify_token',
            'security',
        ]
        
        for i, line in enumerate(lines):
            for pattern in auth_patterns:
                if pattern in line.lower():
                    auth_checks.append({
                        "type": "decorator" if line.strip().startswith('@') else "dependency",
                        "pattern": pattern,
                        "line": i + 1,
                    })
                    break
        
        return auth_checks
    
    def extract_datastore_access(self, tree: Any, content: str) -> List[Dict[str, Any]]:
        """Extract database connection strings and queries."""
        datastores = []
        
        db_urls = re.findall(r'(?:DATABASE_URL|POSTGRES_URL|DB_URI)\s*=\s*["\']([^"\']+)["\']', content)
        for url in db_urls:
            db_name = "postgres"
            match = re.search(r'/(?:[a-zA-Z0-9_\-]+/)?([a-zA-Z0-9_\-]+)$', url.split('?')[0])
            if match:
                db_name = match.group(1)
            datastores.append({
                "connection_url": url,
                "name": db_name,
                "type": "sql",
                "has_writes": "INSERT" in content.upper() or "UPDATE" in content.upper() or "DELETE" in content.upper(),
                "has_reads": "SELECT" in content.upper(),
            })
        
        if not datastores and ('SELECT ' in content.upper() or 'INSERT INTO' in content.upper() or 'UPDATE ' in content.upper()):
            datastores.append({
                "connection_url": None,
                "name": "shared_db",
                "type": "sql",
                "has_writes": "INSERT" in content.upper() or "UPDATE" in content.upper() or "DELETE" in content.upper(),
                "has_reads": "SELECT" in content.upper(),
            })
            
        return datastores

    def extract_secrets(self, content: str) -> List[Dict[str, Any]]:
        """Extract potential hardcoded secrets in source."""
        secrets = []
        lines = content.split('\n')
        for i, line in enumerate(lines):
            secret_match = re.search(r'([a-zA-Z0-9_]*(?:SECRET|KEY|PASSWORD|TOKEN))\s*=\s*["\']([^"\']+)["\']', line)
            if secret_match:
                var_name = secret_match.group(1)
                value = secret_match.group(2)
                if len(value) >= 6 and not value.startswith("os."):
                    secrets.append({
                        "name": var_name,
                        "line": i + 1,
                        "value": value,
                    })
        return secrets
    
    def _has_auth_decorator(self, lines: List[str], endpoint_line: int) -> bool:
        """Check if endpoint has auth decorator above it."""
        for i in range(max(0, endpoint_line - 5), endpoint_line):
            line = lines[i].lower()
            if any(auth in line for auth in ['require_auth', 'jwt_required', 'login_required', 'oauth', 'permission']):
                return True
        return False
