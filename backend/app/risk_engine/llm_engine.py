"""OpenAI LLM integration for AI-assisted risk reasoning and narrative generation."""
import json
import logging
from typing import List, Dict, Any, Optional
import hashlib
from app.config import Settings
from app.models import Finding, Severity, FindingSource
from app.security import hash_secret, redact_dict

logger = logging.getLogger(__name__)

# Response schema for structured outputs
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "title": {"type": "string"},
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1
        },
        "narrative": {"type": "string"},
        "affected_components": {
            "type": "array",
            "items": {"type": "string"}
        },
        "remediation_steps": {
            "type": "array",
            "items": {"type": "string"}
        },
        "references": {
            "type": "array",
            "items": {"type": "string"}
        }
    },
    "required": ["finding_id", "title", "severity", "confidence", "narrative"]
}


class LLMRiskEngine:
    """Engine for AI-assisted risk detection and reasoning."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.enabled = settings.openai.enable_ai_layer and settings.openai.api_key
        
        if self.enabled:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=settings.openai.api_key)
            except ImportError:
                logger.warning("OpenAI library not installed")
                self.enabled = False
    
    def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
        subgraph: Dict[str, Any],
        semgrep_findings: List[Dict[str, Any]],
    ) -> List[Finding]:
        """
        Use LLM to enrich and synthesize findings.
        
        Args:
            findings: Initial findings (deterministic + semgrep)
            subgraph: Relevant graph subgraph for context
            semgrep_findings: Raw Semgrep findings
            
        Returns:
            Enriched Finding objects
        """
        if not self.enabled:
            logger.info("AI layer disabled, returning deterministic findings only")
            return []
        
        enriched = []
        
        # Batch findings for efficiency
        for finding in findings:
            # Check cache first
            cache_key = self._compute_cache_key(finding)
            cached = self._get_cached_response(cache_key)
            
            if cached:
                enriched.append(cached)
                continue
            
            try:
                # Call LLM for enrichment
                llm_response = self._call_llm(
                    finding,
                    subgraph,
                    semgrep_findings,
                )
                
                # Convert to Finding object
                enriched_finding = self._response_to_finding(llm_response, finding)
                enriched.append(enriched_finding)
                
                # Cache response
                self._cache_response(cache_key, llm_response)
            
            except Exception as e:
                logger.error(f"LLM enrichment failed for finding {finding.get('id')}: {e}")
                # Fallback to deterministic finding
                enriched.append(self._finding_dict_to_object(finding))
        
        return enriched
    
    def _call_llm(
        self,
        finding: Dict[str, Any],
        subgraph: Dict[str, Any],
        semgrep_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Call OpenAI API with structured output."""
        
        # Redact secrets before sending to LLM
        safe_finding = redact_dict(finding)
        safe_subgraph = redact_dict(subgraph)
        safe_semgrep = [redact_dict(f) for f in semgrep_findings]
        
        prompt = self._build_prompt(safe_finding, safe_subgraph, safe_semgrep)
        
        try:
            response = self.client.beta.chat.completions.parse(
                model=self.settings.openai.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are an expert security architect analyzing software architecture risks. 
Your task is to synthesize findings from multiple signal sources and produce a clear, actionable risk assessment.
Focus on practical severity, real business impact, and concrete remediation steps."""
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "RiskFinding",
                        "schema": FINDING_SCHEMA,
                        "strict": True
                    }
                },
                temperature=self.settings.openai.temperature,
                timeout=self.settings.openai.timeout,
            )
            
            # Parse response
            content = response.choices[0].message.content
            parsed = json.loads(content)
            return parsed
        
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            raise
    
    def _build_prompt(
        self,
        finding: Dict[str, Any],
        subgraph: Dict[str, Any],
        semgrep_findings: List[Dict[str, Any]],
    ) -> str:
        """Build the prompt for LLM analysis."""
        
        prompt = f"""
Analyze the following architectural risk finding and provide a structured assessment:

## Finding Details
Title: {finding.get('title')}
Description: {finding.get('description')}
Source: {finding.get('source')}
Affected Components: {', '.join(finding.get('affected_components', []))}

## Architecture Context
{json.dumps(subgraph, indent=2)}

## Related Semgrep Findings
{json.dumps(semgrep_findings, indent=2)}

Provide your analysis in JSON format with:
1. **title**: Clear, specific finding title
2. **severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
3. **confidence**: 0-1 confidence score
4. **narrative**: 2-3 sentence summary of the risk and impact
5. **affected_components**: List of component IDs this affects
6. **remediation_steps**: 3-5 concrete remediation steps
7. **references**: Links to relevant resources

Ensure severity assessment considers:
- Accessibility (is this exposed to untrusted inputs?)
- Business impact (how many critical services depend on this?)
- Exploitability (how easy is this to exploit?)
- Data sensitivity (does this access sensitive data?)
"""
        
        return prompt
    
    def _compute_cache_key(self, finding: Dict[str, Any]) -> str:
        """Compute a cache key for a finding."""
        key_data = json.dumps({
            "title": finding.get("title"),
            "description": finding.get("description"),
            "source": finding.get("source"),
        }, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[Finding]:
        """Get cached LLM response."""
        # In production, use Redis or similar
        # For now, just return None (no caching)
        return None
    
    def _cache_response(self, cache_key: str, response: Dict[str, Any]):
        """Cache LLM response."""
        # TODO: Implement caching
        pass
    
    def _response_to_finding(self, llm_response: Dict[str, Any], original: Dict[str, Any]) -> Finding:
        """Convert LLM response to Finding object."""
        return Finding(
            id=llm_response.get("finding_id", original.get("id")),
            scan_id=original.get("scan_id"),
            title=llm_response.get("title", original.get("title")),
            description=llm_response.get("narrative", original.get("description")),
            severity=Severity[llm_response.get("severity", "MEDIUM")],
            confidence=llm_response.get("confidence", 0.8),
            source=FindingSource.LLM if original.get("source") != FindingSource.SEMGREP else FindingSource.HYBRID,
            affected_components=llm_response.get("affected_components", original.get("affected_components", [])),
            remediation_steps=llm_response.get("remediation_steps", []),
            references=llm_response.get("references", []),
        )
    
    def _finding_dict_to_object(self, finding_dict: Dict[str, Any]) -> Finding:
        """Convert finding dictionary to Finding object."""
        return Finding(
            id=finding_dict.get("id"),
            scan_id=finding_dict.get("scan_id"),
            title=finding_dict.get("title"),
            description=finding_dict.get("description"),
            severity=Severity[finding_dict.get("severity", "MEDIUM")],
            confidence=finding_dict.get("confidence", 0.5),
            source=FindingSource[finding_dict.get("source", "DETERMINISTIC")],
            affected_components=finding_dict.get("affected_components", []),
        )
