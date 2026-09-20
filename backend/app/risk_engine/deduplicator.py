"""Risk finding deduplication and synthesis."""
import logging
from typing import List, Dict, Any
from app.models import Finding, Severity

logger = logging.getLogger(__name__)


class FindingDeduplicator:
    """Deduplicates and merges overlapping findings from different sources."""
    
    @staticmethod
    def deduplicate(findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate findings by merging related/overlapping ones.
        
        Args:
            findings: List of findings potentially with duplicates
            
        Returns:
            Deduplicated list
        """
        if not findings:
            return []
        
        # Group findings by affected components and title category
        groups: Dict[Any, List[Finding]] = {}
        
        for finding in findings:
            key_components = tuple(sorted(finding.affected_components or []))
            base_title = finding.title.split(':')[0].strip().lower()
            key = (key_components, base_title)
            
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)
        
        # Merge findings in each group
        merged = []
        for group in groups.values():
            if len(group) == 1:
                merged.append(group[0])
            else:
                merged_finding = FindingDeduplicator._merge_findings(group)
                merged.append(merged_finding)
        
        return merged
    
    @staticmethod
    def _merge_findings(findings: List[Finding]) -> Finding:
        """
        Merge multiple related findings into one.
        
        Args:
            findings: List of related findings to merge
            
        Returns:
            Single merged finding
        """
        # Use the highest severity
        highest_severity = max(findings, key=lambda f: _severity_rank(f.severity)).severity
        highest_confidence = max(f.confidence for f in findings)
        
        # Combine all sources
        sources = set(
            f.source.value if hasattr(f.source, 'value') else str(f.source)
            for f in findings
        )
        
        # Merge descriptions and remediation
        descriptions = [f.description for f in findings if f.description]
        remediation_steps = list(dict.fromkeys(
            step for f in findings for step in (f.remediation_steps or [])
        ))
        
        cwe_ids = list(dict.fromkeys(
            c for f in findings for c in (f.cwe_ids or [])
        ))
        owasp_categories = list(dict.fromkeys(
            o for f in findings for o in (f.owasp_categories or [])
        ))
        references = list(dict.fromkeys(
            ref for f in findings for ref in (f.references or [])
        ))
        
        # Keep the first finding as base
        base = findings[0]
        
        return Finding(
            id=base.id,
            scan_id=base.scan_id,
            title=base.title,
            description="\n".join(dict.fromkeys(descriptions)),
            severity=highest_severity,
            confidence=highest_confidence,
            source=base.source,
            source_rule=getattr(base, 'source_rule', None) or base.semgrep_rule_id or base.cypher_rule_name,
            affected_components=list(dict.fromkeys(
                c for f in findings for c in (f.affected_components or [])
            )),
            affected_endpoints=list(dict.fromkeys(
                e for f in findings for e in (f.affected_endpoints or [])
            )),
            affected_data_stores=list(dict.fromkeys(
                d for f in findings for d in (f.affected_data_stores or [])
            )),
            cwe_ids=cwe_ids,
            owasp_categories=owasp_categories,
            remediation_steps=remediation_steps,
            references=references,
            is_duplicate=True if len(findings) > 1 else False,
        )


def _severity_rank(severity: Any) -> int:
    """Get numeric rank of severity for comparison."""
    sev_val = severity.value.upper() if hasattr(severity, 'value') else str(severity).upper()
    ranks = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    return ranks.get(sev_val, 0)
