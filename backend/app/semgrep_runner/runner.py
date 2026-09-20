"""Semgrep integration for static security analysis."""
import subprocess
import json
import logging
import shutil
import sys
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.config import Settings

logger = logging.getLogger(__name__)

RULE_REMEDIATIONS = {
    "hardcoded-secret": [
        "Move sensitive keys and credentials to environment variables",
        "Use a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)",
        "Rotate the compromised key immediately",
    ],
    "unencrypted-http-call": [
        "Use HTTPS/TLS for all inter-service communications",
        "Enforce transport layer encryption with mTLS",
        "Configure HTTP clients with TLS certificate validation",
    ],
    "missing-input-validation": [
        "Validate all request parameters against strict schemas",
        "Enforce type, length, and format restrictions on input data",
        "Use parameterized queries and avoid string concatenation",
    ],
    "missing-auth-endpoint": [
        "Add authentication middleware or dependency to this endpoint",
        "Enforce role-based access control (RBAC)",
        "Require valid JWT token or API key for non-public routes",
    ],
    "hardcoded-database-password": [
        "Move database credentials to secure environment variables",
        "Use IAM database authentication or secrets manager",
        "Ensure connection strings are not hardcoded in source code",
    ],
    "missing-rate-limiting": [
        "Implement rate limiting middleware on public endpoints",
        "Use token bucket or sliding window algorithms to throttle requests",
        "Configure per-IP or per-user rate limit quotas",
    ],
}


class SemgrepRunner:
    """Wrapper for Semgrep static analysis tool."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.timeout = settings.semgrep.timeout
        self.config_url = settings.semgrep.config_url
    
    def _find_semgrep(self) -> str:
        """Find the semgrep executable."""
        which_path = shutil.which("semgrep")
        if which_path:
            return which_path
        
        # Check python env bin dir
        bin_dir = Path(sys.executable).parent
        candidate = bin_dir / "semgrep"
        if candidate.exists():
            return str(candidate)
        
        return "semgrep"

    def run(self, target_path: str, config: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Semgrep on a target directory.
        
        Args:
            target_path: Directory to scan
            config: Semgrep config string or URL
            
        Returns:
            Parsed Semgrep output with findings
        """
        try:
            semgrep_bin = self._find_semgrep()
            cmd = [semgrep_bin, "--json", "--metrics=off", "--disable-version-check"]
            
            # Add target
            cmd.append(target_path)
            
            # Determine config to use
            rule_pack_mgr = RulePackManager(self.settings)
            custom_config = rule_pack_mgr.load_custom_rules()
            
            if config:
                cmd.extend(["-c", config])
            elif custom_config:
                cmd.extend(["-c", custom_config])
            else:
                cmd.extend(["-c", self.config_url])
            
            # Add timeout
            cmd.extend(["--timeout", str(self.timeout)])
            
            # Run Semgrep
            logger.info(f"Running Semgrep: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 10,
            )
            
            # Parse output from stdout if available
            if result.stdout and result.stdout.strip().startswith("{"):
                try:
                    output = json.loads(result.stdout)
                    findings = self._normalize_findings(output.get("results", []))
                    return {
                        "findings": findings,
                        "errors": output.get("errors", []),
                        "stats": output.get("stats", {}),
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Semgrep output: {e}")
            
            if result.returncode not in [0, 1]:
                logger.warning(f"Semgrep returncode {result.returncode}: {result.stderr}")
                return {"findings": [], "errors": [result.stderr]}
            
            return {"findings": [], "errors": []}
        
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep timeout after {self.timeout}s")
            return {"findings": [], "errors": ["Semgrep timeout"]}
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}")
            return {"findings": [], "errors": [str(e)]}
    
    def _normalize_findings(self, semgrep_results: List[Dict]) -> List[Dict[str, Any]]:
        """
        Normalize Semgrep findings to a common schema.
        
        Args:
            semgrep_results: Raw Semgrep results
            
        Returns:
            Normalized findings
        """
        findings = []
        
        for result in semgrep_results:
            raw_rule_id = result.get("check_id", "semgrep-rule")
            base_rule_id = raw_rule_id.split(".")[-1]
            
            metadata = result.get("extra", {}).get("metadata", {})
            
            # Determine severity
            raw_severity = result.get("extra", {}).get("severity", "").upper()
            meta_severity = metadata.get("severity", "").upper()
            
            if raw_severity == "CRITICAL" or meta_severity == "CRITICAL":
                severity = "CRITICAL"
            elif raw_severity == "ERROR" or meta_severity == "HIGH":
                severity = "HIGH"
            elif raw_severity == "WARNING" or meta_severity == "MEDIUM":
                severity = "MEDIUM"
            elif raw_severity == "INFO" or meta_severity == "LOW":
                severity = "LOW"
            else:
                severity = "MEDIUM"
            
            # Extract CWE/OWASP
            cwe_ids = []
            owasp_categories = []
            
            if "cwe" in metadata:
                val = metadata["cwe"]
                if isinstance(val, list):
                    cwe_ids = val
                elif isinstance(val, (int, str)):
                    cwe_ids = [val]
            elif "cwe_ids" in metadata:
                cwe_ids = metadata["cwe_ids"]
            
            if not cwe_ids:
                # Default CWE mapping for common rules
                if "secret" in base_rule_id:
                    cwe_ids = ["CWE-798"]
                elif "unencrypted" in base_rule_id:
                    cwe_ids = ["CWE-319"]
                elif "auth" in base_rule_id:
                    cwe_ids = ["CWE-306"]
                elif "input" in base_rule_id:
                    cwe_ids = ["CWE-20"]
                elif "rate" in base_rule_id:
                    cwe_ids = ["CWE-770"]
                else:
                    cwe_ids = ["CWE-1088"]
            
            if "owasp" in metadata:
                val = metadata["owasp"]
                if isinstance(val, list):
                    owasp_categories = val
                else:
                    owasp_categories = [str(val)]
            else:
                owasp_categories = ["A01:2021 - Broken Access Control"]
            
            # Remediation
            remediation_steps = RULE_REMEDIATIONS.get(base_rule_id, [
                "Review and apply security best practices for this pattern",
                "Ensure strict input validation and access controls",
            ])
            
            file_path = result.get("path", "")
            # Derive component from file path
            parts = Path(file_path).parts
            component = parts[0] if parts else "service"
            if len(parts) > 1 and parts[0] in ["test-fixtures", "demo-repo"]:
                component = parts[-2]
            
            message = result.get("extra", {}).get("message", "")
            title = f"{base_rule_id.replace('-', ' ').title()}: {Path(file_path).name}"
            if "secret" in base_rule_id:
                title = f"Hardcoded Secret in {Path(file_path).parent.name}"
            elif "auth" in base_rule_id:
                title = f"Unprotected Endpoint in {Path(file_path).parent.name}"
            elif "unencrypted" in base_rule_id:
                title = f"Unencrypted HTTP Call in {Path(file_path).parent.name}"
            elif "rate" in base_rule_id:
                title = f"Missing Rate Limiting in {Path(file_path).parent.name}"
            elif "input" in base_rule_id:
                title = f"Missing Input Validation in {Path(file_path).parent.name}"
            
            finding = {
                "rule_id": raw_rule_id,
                "title": title,
                "description": message or f"Static analysis flagged {base_rule_id} in {file_path}",
                "severity": severity,
                "confidence": 0.95,
                "source": "semgrep",
                "file_path": file_path,
                "line_number": result.get("start", {}).get("line"),
                "column": result.get("start", {}).get("col"),
                "affected_components": [component],
                "cwe_ids": cwe_ids,
                "owasp_categories": owasp_categories,
                "remediation_steps": remediation_steps,
                "references": [
                    f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html"
                    for cwe in cwe_ids if isinstance(cwe, str) and cwe.startswith("CWE-")
                ] or ["https://owasp.org/www-project-top-ten/"],
            }
            
            findings.append(finding)
        
        return findings
    
    def validate_config(self, config: str) -> bool:
        """Check if Semgrep config is valid."""
        try:
            semgrep_bin = self._find_semgrep()
            cmd = [semgrep_bin, "-c", config, "--validate", "--metrics=off"]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Config validation failed: {e}")
            return False


class RulePackManager:
    """Manage Semgrep rule packs."""
    
    DEFAULT_RULES = {
        "owasp-top10": [
            "p/owasp-top-ten",
            "p/security-audit",
        ],
        "secrets": [
            "p/secrets",
        ],
        "common": [
            "p/owasp-top-ten",
            "p/security-audit",
            "p/cwe-top-25",
        ],
    }
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.rules_dir = Path("rules/semgrep")
        if not self.rules_dir.exists():
            # Check relative to repo root
            candidate = Path(__file__).parent.parent.parent.parent / "rules" / "semgrep"
            if candidate.exists():
                self.rules_dir = candidate
    
    def get_config_for_language(self, language: str) -> str:
        """Get Semgrep config for a language."""
        return " ".join(self.DEFAULT_RULES.get("common", []))
    
    def list_available_packs(self) -> List[str]:
        """List available rule packs."""
        return list(self.DEFAULT_RULES.keys())
    
    def load_custom_rules(self) -> Optional[str]:
        """Load custom rules from rules directory."""
        if not self.rules_dir.exists():
            return None
        
        yaml_files = list(self.rules_dir.glob("*.yaml")) + list(self.rules_dir.glob("*.yml"))
        if yaml_files:
            return ",".join(str(f.resolve()) for f in yaml_files)
        
        return None
