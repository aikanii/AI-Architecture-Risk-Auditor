"""Report export formats (JSON, SARIF, HTML, PDF)."""

import json
from datetime import datetime
from typing import List, Dict, Any
from io import BytesIO

from app.models import Scan, Finding


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
                "status": self.scan.status,
                "created_at": self.scan.created_at.isoformat() if self.scan.created_at else None,
                "updated_at": self.scan.updated_at.isoformat() if self.scan.updated_at else None,
                "repository": self.scan.repository_source,
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "affected_components": f.affected_components,
                    "remediation_steps": f.remediation_steps,
                    "cwe_ids": f.cwe_ids,
                    "owasp_categories": f.owasp_categories,
                    "references": f.references,
                    "source": f.source,
                    "source_rule": f.source_rule,
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
        """Export as SARIF (GitHub code scanning format)."""
        # SARIF 2.1.0 schema for GitHub Advanced Security
        results = []
        
        for finding in self.findings:
            result = {
                "ruleId": finding.source_rule or f"finding-{finding.id}",
                "level": self._severity_to_sarif_level(finding.severity),
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
                    for comp in (finding.affected_components or [])
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
                            "informationUri": "https://github.com/yourusername/ai-arch-auditor",
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
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Report: {self.scan.id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 20px; }}
        .stat {{ background: #fff; padding: 15px; border-radius: 8px; border-left: 4px solid #ccc; }}
        .stat.critical {{ border-left-color: #d32f2f; }}
        .stat.high {{ border-left-color: #f57c00; }}
        .stat.medium {{ border-left-color: #fbc02d; }}
        .stat.low {{ border-left-color: #388e3c; }}
        .findings {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .finding {{ border-bottom: 1px solid #eee; padding: 15px 0; }}
        .finding:last-child {{ border-bottom: none; }}
        .finding-title {{ font-weight: 600; font-size: 16px; margin-bottom: 5px; }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; margin-right: 10px; }}
        .severity.CRITICAL {{ background: #ffebee; color: #d32f2f; }}
        .severity.HIGH {{ background: #fff3e0; color: #f57c00; }}
        .severity.MEDIUM {{ background: #fffde7; color: #fbc02d; }}
        .severity.LOW {{ background: #e8f5e9; color: #388e3c; }}
        .components {{ color: #666; font-size: 14px; margin-top: 8px; }}
        .remediation {{ background: #f5f5f5; padding: 10px; border-radius: 4px; margin-top: 10px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Architecture Risk Audit Report</h1>
        <p><strong>Scan ID:</strong> {self.scan.id}</p>
        <p><strong>Date:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
        <p><strong>Repository:</strong> {self.scan.repository_source}</p>
    </div>
    
    <div class="summary">
        <div class="stat critical">
            <div style="font-size: 24px; font-weight: bold;">{self._count_by_severity().get("CRITICAL", 0)}</div>
            <div style="font-size: 12px; color: #d32f2f;">Critical</div>
        </div>
        <div class="stat high">
            <div style="font-size: 24px; font-weight: bold;">{self._count_by_severity().get("HIGH", 0)}</div>
            <div style="font-size: 12px; color: #f57c00;">High</div>
        </div>
        <div class="stat medium">
            <div style="font-size: 24px; font-weight: bold;">{self._count_by_severity().get("MEDIUM", 0)}</div>
            <div style="font-size: 12px; color: #fbc02d;">Medium</div>
        </div>
        <div class="stat low">
            <div style="font-size: 24px; font-weight: bold;">{self._count_by_severity().get("LOW", 0)}</div>
            <div style="font-size: 12px; color: #388e3c;">Low</div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Findings ({len(self.findings)} total)</h2>
        {findings_html}
    </div>
</body>
</html>
"""
    
    def export_pdf(self) -> bytes:
        """Export as PDF using reportlab."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
            from reportlab.lib import colors
        except ImportError:
            raise ImportError("reportlab required for PDF export. Install with: pip install reportlab")
        
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f1f1f'),
            spaceAfter=12,
        )
        
        # Title
        story.append(Paragraph("Architecture Risk Audit Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Scan info
        info_data = [
            ["Scan ID:", self.scan.id],
            ["Date:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Repository:", str(self.scan.repository_source)],
            ["Findings:", str(len(self.findings))],
        ]
        info_table = Table(info_data)
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Summary
        story.append(Paragraph("Summary", styles['Heading2']))
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(self._count_by_severity().get("CRITICAL", 0))],
            ["High", str(self._count_by_severity().get("HIGH", 0))],
            ["Medium", str(self._count_by_severity().get("MEDIUM", 0))],
            ["Low", str(self._count_by_severity().get("LOW", 0))],
        ]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(PageBreak())
        
        # Findings
        story.append(Paragraph("Findings", styles['Heading2']))
        for i, finding in enumerate(self.findings[:20]):  # Limit to first 20 for brevity
            story.append(Paragraph(
                f"{i+1}. {finding.title}",
                styles['Heading3']
            ))
            story.append(Paragraph(
                f"<b>Severity:</b> {finding.severity} | <b>Confidence:</b> {finding.confidence:.0%}",
                styles['Normal']
            ))
            story.append(Paragraph(
                f"{finding.description}",
                styles['Normal']
            ))
            if finding.remediation_steps:
                story.append(Paragraph(
                    f"<b>Remediation:</b> {'; '.join(finding.remediation_steps[:2])}",
                    styles['Normal']
                ))
            story.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(story)
        return buffer.getvalue()
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in self.findings:
            severity = finding.severity
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_source(self) -> Dict[str, int]:
        """Count findings by source."""
        counts = {}
        for finding in self.findings:
            source = finding.source
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
        return mapping.get(severity, "warning")
    
    def _get_sarif_rules(self) -> List[Dict[str, Any]]:
        """Get SARIF rule definitions."""
        rules = {}
        for finding in self.findings:
            rule_id = finding.source_rule or f"finding-{finding.id}"
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
                        "text": "\n".join(finding.remediation_steps or []) or "See references for details"
                    },
                    "helpUri": finding.references[0] if finding.references else None,
                    "properties": {
                        "tags": finding.owasp_categories or [],
                    }
                }
        return list(rules.values())
    
    def _finding_to_html(self, finding: Finding) -> str:
        """Convert finding to HTML."""
        return f"""
        <div class="finding">
            <div class="finding-title">
                <span class="severity {finding.severity}">{finding.severity}</span>
                {finding.title}
            </div>
            <p>{finding.description}</p>
            <div class="components">
                <strong>Affected:</strong> {", ".join(finding.affected_components or ["N/A"])}
            </div>
            {'<div class="remediation">' + '<br>'.join(finding.remediation_steps[:2]) + '</div>' if finding.remediation_steps else ''}
        </div>
        """
