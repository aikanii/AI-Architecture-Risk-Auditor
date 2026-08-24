"""Semgrep integration for static security analysis."""
import subprocess
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from app.config import Settings

logger = logging.getLogger(__name__)


class SemgrepRunner:
    """Wrapper for Semgrep static analysis tool."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.timeout = settings.semgrep.timeout
        self.config_url = settings.semgrep.config_url
    
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
            cmd = ["semgrep", "--json"]
            
            # Add target
            cmd.append(target_path)
            
            # Add config
            if config:
                cmd.extend(["-c", config])
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
            
            if result.returncode not in [0, 1]:  # 0 = no findings, 1 = findings found
                logger.error(f"Semgrep error: {result.stderr}")
                return {"findings": [], "errors": [result.stderr]}
            
            # Parse output
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
                return {"findings": [], "errors": [str(e)]}
        
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
            # Extract severity from metadata
            metadata = result.get("extra", {}).get("metadata", {})
            severity = metadata.get("severity", "MEDIUM").upper()
            
            # Map Semgrep severity to our levels
            semgrep_severity = result.get("extra", {}).get("severity", "WARNING").upper()
            if semgrep_severity == "ERROR":
                severity = "HIGH"
            elif semgrep_severity == "WARNING":
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Extract CWE/OWASP
            cwe_ids = []
            owasp_categories = []
            
            if "cwe" in metadata:
                cwe_ids = [metadata["cwe"]] if isinstance(metadata["cwe"], str) else metadata.get("cwe", [])
            
            if "owasp" in metadata:
                owasp_categories = metadata.get("owasp", [])
            
            finding = {
                "rule_id": result.get("check_id"),
                "title": result.get("check_id", "Unknown Rule"),
                "message": result.get("extra", {}).get("message", result.get("extra", {}).get("description", "")),
                "severity": severity,
                "confidence": 0.9,  # Semgrep findings are high-confidence
                "source": "semgrep",
                "file_path": result.get("path"),
                "line_number": result.get("start", {}).get("line"),
                "column": result.get("start", {}).get("col"),
                "cwe_ids": cwe_ids,
                "owasp_categories": owasp_categories,
            }
            
            findings.append(finding)
        
        return findings
    
    def validate_config(self, config: str) -> bool:
        """Check if Semgrep config is valid."""
        try:
            cmd = ["semgrep", "-c", config, "--validate"]
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
    
    def get_config_for_language(self, language: str) -> str:
        """Get Semgrep config for a language."""
        # Return default config URLs
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
            # Semgrep can combine multiple config files
            return ",".join(str(f) for f in yaml_files)
        
        return None
