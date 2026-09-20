"""Report export formats (JSON, SARIF, HTML, PDF)."""

import json
from datetime import datetime
from typing import List, Dict, Any, Union
from io import BytesIO

from app.models import Scan, Finding, Severity


class ReportExporter:
    """Export findings in multiple formats."""
    
    def __init__(self, scan: Scan, findings: List[Finding]):
        """Initialize with scan and findings."""
        self.scan = scan
        self.findings = findings
    
    def export_json(self) -> Dict[str, Any]:
        """Export as JSON."""
        return {
            "scan": {
                "id": self.scan.id,
                "status": self.scan.status.value if hasattr(self.scan.status, 'value') else str(self.scan.status),
                "created_at": self.scan.created_at.isoformat() if self.scan.created_at else None,
                "updated_at": self.scan.updated_at.isoformat() if self.scan.updated_at else None,
                "repository": self.scan.repository_source,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "confidence": f.confidence,
                    "description": f.description,
                    "affected_components": f.affected_components,
                    "remediation_steps": f.remediation_steps,
                    "cwe_ids": f.cwe_ids,
                    "owasp_categories": f.owasp_categories,
                    "references": f.references,
                    "source": f.source.value if hasattr(f.source, 'value') else str(f.source),
                    "source_rule": getattr(f, 'source_rule', None) or f.semgrep_rule_id or f.cypher_rule_name or f"finding-{f.id}",
                }
                for f in self.findings
            ],
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self._count_by_severity(),
                "by_source": self._count_by_source(),
            }
        }
    
    def export_sarif(self) -> Dict[str, Any]:
        """Export as SARIF 2.1.0 (GitHub code scanning format)."""
        results = []
        
        for finding in self.findings:
            sev_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            rule_id = getattr(finding, 'source_rule', None) or finding.semgrep_rule_id or finding.cypher_rule_name or f"finding-{finding.id}"
            
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(sev_str),
                "message": {
                    "text": finding.title,
                    "markdown": finding.description,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": comp if isinstance(comp, str) else str(comp)
                            }
                        }
                    }
                    for comp in (finding.affected_components or ["repository"])
                ],
                "properties": {
                    "confidence": str(finding.confidence),
                    "cwe": ",".join(map(str, finding.cwe_ids or [])),
                    "owasp": ",".join(finding.owasp_categories or []),
                }
            }
            results.append(result)
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AI Architecture Risk Auditor",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/aikanii/AI-Architecture-Risk-Auditor",
                            "rules": self._get_sarif_rules(),
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanId": self.scan.id,
                        "scanTime": self.scan.created_at.isoformat() if self.scan.created_at else None,
                    }
                }
            ]
        }
    
    def export_html(self) -> str:
        """Export as interactive HTML."""
        findings_html = "\n".join([
            self._finding_to_html(f) for f in self.findings
        ])
        
        counts = self._count_by_severity()
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Report: {self.scan.id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f5f5f5; color: #212121; }}
        .header {{ background: #fff; padding: 24px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 20px; }}
        .stat {{ background: #fff; padding: 20px; border-radius: 8px; border-left: 5px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat.critical {{ border-left-color: #d32f2f; }}
        .stat.high {{ border-left-color: #f57c00; }}
        .stat.medium {{ border-left-color: #fbc02d; }}
        .stat.low {{ border-left-color: #388e3c; }}
        .findings {{ background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .finding {{ border-bottom: 1px solid #eee; padding: 20px 0; }}
        .finding:last-child {{ border-bottom: none; }}
        .finding-title {{ font-weight: 600; font-size: 18px; margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }}
        .severity {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 700; color: #fff; }}
        .severity.CRITICAL {{ background: #d32f2f; }}
        .severity.HIGH {{ background: #f57c00; }}
        .severity.MEDIUM {{ background: #fbc02d; color: #000; }}
        .severity.LOW {{ background: #388e3c; }}
        .components {{ color: #555; font-size: 14px; margin-top: 10px; }}
        .remediation {{ background: #f8f9fa; border-left: 3px solid #2196F3; padding: 12px; border-radius: 4px; margin-top: 12px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🏛️ Architecture Risk Audit Report</h1>
        <p><strong>Scan ID:</strong> {self.scan.id}</p>
        <p><strong>Date:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        <p><strong>Repository:</strong> {json.dumps(self.scan.repository_source)}</p>
    </div>
    
    <div class="summary">
        <div class="stat critical">
            <div style="font-size: 28px; font-weight: bold; color: #d32f2f;">{counts.get("CRITICAL", 0)}</div>
            <div style="font-size: 13px; font-weight: 600;">Critical Risks</div>
        </div>
        <div class="stat high">
            <div style="font-size: 28px; font-weight: bold; color: #f57c00;">{counts.get("HIGH", 0)}</div>
            <div style="font-size: 13px; font-weight: 600;">High Risks</div>
        </div>
        <div class="stat medium">
            <div style="font-size: 28px; font-weight: bold; color: #fbc02d;">{counts.get("MEDIUM", 0)}</div>
            <div style="font-size: 13px; font-weight: 600;">Medium Risks</div>
        </div>
        <div class="stat low">
            <div style="font-size: 28px; font-weight: bold; color: #388e3c;">{counts.get("LOW", 0)}</div>
            <div style="font-size: 13px; font-weight: 600;">Low Risks</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Detected Risks ({len(self.findings)} total)</h2>
        {findings_html}
    </div>
</body>
</html>
"""
    
    def export_pdf(self) -> bytes:
        """Export as PDF using reportlab."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
            from reportlab.lib import colors
        except ImportError:
            raise ImportError("reportlab required for PDF export. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#1f1f1f'),
            spaceAfter=12,
        )
        
        story.append(Paragraph("Architecture Risk Audit Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        info_data = [
            ["Scan ID:", str(self.scan.id)],
            ["Date:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Repository:", str(self.scan.repository_source)],
            ["Total Findings:", str(len(self.findings))],
        ]
        info_table = Table(info_data, colWidths=[1.5*inch, 5.0*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.25*inch))
        
        story.append(Paragraph("Severity Summary", styles['Heading2']))
        counts = self._count_by_severity()
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(counts.get("CRITICAL", 0))],
            ["High", str(counts.get("HIGH", 0))],
            ["Medium", str(counts.get("MEDIUM", 0))],
            ["Low", str(counts.get("LOW", 0))],
        ]
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2196F3')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Risk Findings", styles['Heading2']))
        for i, finding in enumerate(self.findings[:25]):
            sev_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            story.append(Paragraph(
                f"<b>{i+1}. {finding.title}</b> [{sev_str}]",
                styles['Heading3']
            ))
            story.append(Paragraph(
                f"{finding.description}",
                styles['Normal']
            ))
            if finding.remediation_steps:
                remed = "<br/>• ".join(finding.remediation_steps[:3])
                story.append(Paragraph(
                    f"<b>Remediation:</b><br/>• {remed}",
                    styles['Normal']
                ))
            story.append(Spacer(1, 0.15*inch))
        
        doc.build(story)
        return buffer.getvalue()
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in self.findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _count_by_source(self) -> Dict[str, int]:
        """Count findings by source."""
        counts = {}
        for finding in self.findings:
            source = finding.source.value if hasattr(finding.source, 'value') else str(finding.source)
            counts[source] = counts.get(source, 0) + 1
        return counts
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity.upper(), "warning")
    
    def _get_sarif_rules(self) -> List[Dict[str, Any]]:
        """Get SARIF rule definitions."""
        rules = {}
        for finding in self.findings:
            rule_id = getattr(finding, 'source_rule', None) or finding.semgrep_rule_id or finding.cypher_rule_name or f"finding-{finding.id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description or ""
                    },
                    "help": {
                        "text": "\n".join(finding.remediation_steps or []) or "Apply recommended security architecture mitigations."
                    },
                    "helpUri": finding.references[0] if finding.references else "https://owasp.org",
                    "properties": {
                        "tags": finding.owasp_categories or [],
                    }
                }
        return list(rules.values())
    
    def _finding_to_html(self, finding: Finding) -> str:
        """Convert finding to HTML."""
        sev_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        remed_html = ""
        if finding.remediation_steps:
            remed_html = f"<div class='remediation'><strong>Remediation:</strong><br/>" + "<br/>".join(f"• {s}" for s in finding.remediation_steps) + "</div>"
            
        return f"""
        <div class="finding">
            <div class="finding-title">
                <span class="severity {sev_str}">{sev_str}</span>
                {finding.title}
            </div>
            <p>{finding.description}</p>
            <div class="components">
                <strong>Affected:</strong> {", ".join(map(str, finding.affected_components or ["General"]))}
                | <strong>CWE:</strong> {", ".join(map(str, finding.cwe_ids or ["N/A"]))}
            </div>
            {remed_html}
        </div>
        """
