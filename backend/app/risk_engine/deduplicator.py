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
        
        # Group findings by affected components and type
        groups: Dict[str, List[Finding]] = {}
        
        for finding in findings:
            # Create grouping key based on affected components and title pattern
            key_components = tuple(sorted(finding.affected_components))
            key = (key_components, finding.title.split(':')[0])  # Use base title
            
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
        sources = set(f.source.value for f in findings)
        is_hybrid = len(sources) > 1
        
        # Merge descriptions and remediation
        descriptions = [f.description for f in findings if f.description]
        remediation_steps = list(dict.fromkeys(
            step for f in findings for step in f.remediation_steps
        ))
        
        # Keep the first finding as base
        base = findings[0]
        
        return Finding(
            id=base.id,
            scan_id=base.scan_id,
            title=base.title,
            description="\n".join(descriptions),
            severity=highest_severity,
            confidence=highest_confidence,
            source=base.source,  # Keep original primary source
            affected_components=list(set(
                c for f in findings for c in f.affected_components
            )),
            affected_endpoints=list(set(
                e for f in findings for e in f.affected_endpoints
            )),
            affected_data_stores=list(set(
                d for f in findings for d in f.affected_data_stores
            )),
            remediation_steps=remediation_steps,
            references=list(dict.fromkeys(
                ref for f in findings for ref in f.references
            )),
            is_duplicate=True if len(findings) > 1 else False,
        )


def _severity_rank(severity: Severity) -> int:
    """Get numeric rank of severity for comparison."""
    ranks = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    return ranks.get(severity, 0)
