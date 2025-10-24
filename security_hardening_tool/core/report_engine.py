"""Report generation engine for security hardening tool."""

import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    PageBreak, Image, KeepTogether
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from .interfaces import ReportEngine
from .models import (
    AssessmentResult, HardeningResult, OperationResult, 
    Severity, SystemInfo, OSInfo
)
from .interfaces import Logger
from .compliance_frameworks import ComplianceFrameworkMapper, ComplianceFramework


class PDFReportEngine(ReportEngine):
    """PDF report generation engine using ReportLab."""
    
    def __init__(self, logger: Logger, system_info: Optional[SystemInfo] = None):
        """Initialize the report engine.
        
        Args:
            logger: Logger instance for audit trail
            system_info: System information for report headers
        """
        self.logger = logger
        self.system_info = system_info
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Initialize compliance framework mapper
        self.compliance_mapper = ComplianceFrameworkMapper()
    
    def _setup_custom_styles(self):
        """Set up custom paragraph styles for reports."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.darkblue
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkgreen
        ))
        
        # Critical finding style
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontName='Helvetica-Bold'
        ))
        
        # High finding style
        self.styles.add(ParagraphStyle(
            name='High',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontName='Helvetica-Bold'
        ))
        
        # Medium finding style
        self.styles.add(ParagraphStyle(
            name='Medium',
            parent=self.styles['Normal'],
            textColor=colors.yellow,
            fontName='Helvetica-Bold'
        ))
        
        # Low finding style
        self.styles.add(ParagraphStyle(
            name='Low',
            parent=self.styles['Normal'],
            textColor=colors.lightblue,
            fontName='Helvetica-Bold'
        ))
    
    def _load_framework_mappings(self) -> Dict[str, Dict[str, List[str]]]:
        """Load compliance framework mappings for parameters."""
        return {
            'CIS': {
                'windows': [
                    'account_policies', 'local_policies', 'security_options',
                    'system_services', 'firewall_settings', 'audit_policies'
                ],
                'linux': [
                    'filesystem_config', 'package_management', 'services',
                    'network_config', 'firewall', 'access_control',
                    'user_accounts', 'logging_auditing', 'system_maintenance'
                ]
            },
            'NIST': {
                'access_control': ['AC-2', 'AC-3', 'AC-6', 'AC-7'],
                'audit_accountability': ['AU-2', 'AU-3', 'AU-6', 'AU-12'],
                'configuration_management': ['CM-2', 'CM-6', 'CM-7'],
                'identification_authentication': ['IA-2', 'IA-5', 'IA-8'],
                'system_communications': ['SC-7', 'SC-8', 'SC-13']
            },
            'ISO27001': {
                'access_control': ['A.9.1', 'A.9.2', 'A.9.4'],
                'cryptography': ['A.10.1'],
                'operations_security': ['A.12.1', 'A.12.2', 'A.12.6'],
                'communications_security': ['A.13.1', 'A.13.2'],
                'system_acquisition': ['A.14.1', 'A.14.2']
            }
        }   
 
    def generate_assessment_report(self, results: List[AssessmentResult], 
                                 output_path: str) -> OperationResult:
        """Generate comprehensive assessment report with charts and analysis.
        
        Args:
            results: List of assessment results
            output_path: Path to save the PDF report
            
        Returns:
            OperationResult indicating success/failure
        """
        try:
            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page("Security Assessment Report"))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(results))
            story.append(PageBreak())
            
            # Assessment overview with charts
            story.extend(self._create_assessment_overview(results))
            story.append(PageBreak())
            
            # Detailed findings by severity
            story.extend(self._create_detailed_findings(results))
            story.append(PageBreak())
            
            # Remediation recommendations
            story.extend(self._create_remediation_section(results))
            
            # Build PDF
            doc.build(story)
            
            self.logger.log_operation(
                "generate_assessment_report",
                {"output_path": output_path, "findings_count": len(results)},
                success=True
            )
            
            return OperationResult(
                success=True,
                message=f"Assessment report generated successfully: {output_path}",
                data={"report_path": output_path, "findings_count": len(results)}
            )
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "generate_assessment_report"})
            return OperationResult(
                success=False,
                message=f"Failed to generate assessment report: {str(e)}",
                errors=[str(e)]
            )
    
    def generate_hardening_report(self, results: List[HardeningResult], 
                                output_path: str) -> OperationResult:
        """Generate hardening operation report with before/after documentation.
        
        Args:
            results: List of hardening results
            output_path: Path to save the PDF report
            
        Returns:
            OperationResult indicating success/failure
        """
        try:
            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page("Security Hardening Report"))
            story.append(PageBreak())
            
            # Executive summary for hardening
            story.extend(self._create_hardening_summary(results))
            story.append(PageBreak())
            
            # Before/after comparison charts
            story.extend(self._create_before_after_analysis(results))
            story.append(PageBreak())
            
            # Detailed hardening results
            story.extend(self._create_hardening_details(results))
            story.append(PageBreak())
            
            # Rollback information
            story.extend(self._create_rollback_section(results))
            
            # Build PDF
            doc.build(story)
            
            self.logger.log_operation(
                "generate_hardening_report",
                {"output_path": output_path, "changes_count": len(results)},
                success=True
            )
            
            return OperationResult(
                success=True,
                message=f"Hardening report generated successfully: {output_path}",
                data={"report_path": output_path, "changes_count": len(results)}
            )
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "generate_hardening_report"})
            return OperationResult(
                success=False,
                message=f"Failed to generate hardening report: {str(e)}",
                errors=[str(e)]
            )
    
    def generate_compliance_report(self, results: List[AssessmentResult], 
                                 framework: str, output_path: str) -> OperationResult:
        """Generate compliance framework-specific report.
        
        Args:
            results: List of assessment results
            framework: Compliance framework (CIS, NIST, ISO27001)
            output_path: Path to save the PDF report
            
        Returns:
            OperationResult indicating success/failure
        """
        try:
            # Validate framework
            try:
                framework_enum = ComplianceFramework(framework.upper())
            except ValueError:
                supported_frameworks = [f.value for f in ComplianceFramework]
                return OperationResult(
                    success=False,
                    message=f"Unsupported compliance framework: {framework}. Supported: {', '.join(supported_frameworks)}",
                    errors=[f"Framework {framework} not supported"]
                )
            
            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page(f"{framework.upper()} Compliance Report"))
            story.append(PageBreak())
            
            # Compliance executive summary
            story.extend(self._create_compliance_summary(results, framework))
            story.append(PageBreak())
            
            # Framework-specific analysis
            story.extend(self._create_framework_analysis(results, framework_enum))
            story.append(PageBreak())
            
            # Gap analysis and recommendations
            story.extend(self._create_gap_analysis(results, framework_enum))
            story.append(PageBreak())
            
            # Compliance matrix
            story.extend(self._create_compliance_matrix(results, framework_enum))
            
            # Build PDF
            doc.build(story)
            
            self.logger.log_operation(
                "generate_compliance_report",
                {"output_path": output_path, "framework": framework, "findings_count": len(results)},
                success=True
            )
            
            return OperationResult(
                success=True,
                message=f"{framework} compliance report generated successfully: {output_path}",
                data={"report_path": output_path, "framework": framework, "findings_count": len(results)}
            )
            
        except Exception as e:
            self.logger.log_error(e, {"operation": "generate_compliance_report"})
            return OperationResult(
                success=False,
                message=f"Failed to generate compliance report: {str(e)}",
                errors=[str(e)]
            )    

    def _create_title_page(self, title: str) -> List:
        """Create title page for reports."""
        story = []
        
        # Main title
        story.append(Paragraph(title, self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # System information
        if self.system_info:
            story.append(Paragraph("System Information", self.styles['CustomSubtitle']))
            
            system_data = [
                ["Hostname:", self.system_info.hostname],
                ["Operating System:", f"{self.system_info.os_info.platform.value.title()} {self.system_info.os_info.version}"],
                ["Architecture:", self.system_info.os_info.architecture.value],
                ["Domain:", self.system_info.domain or "N/A"],
            ]
            
            system_table = Table(system_data, colWidths=[2*inch, 4*inch])
            system_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(system_table)
        
        story.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        story.append(Paragraph("Report Information", self.styles['CustomSubtitle']))
        
        report_data = [
            ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Tool:", "Security Hardening Tool v1.0"],
            ["Report Type:", title],
        ]
        
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(report_table)
        
        return story
    
    def _create_executive_summary(self, results: List[AssessmentResult]) -> List:
        """Create executive summary section for assessment reports."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['CustomSubtitle']))
        
        # Calculate summary statistics
        total_findings = len(results)
        non_compliant = len([r for r in results if not r.compliant])
        compliant = total_findings - non_compliant
        
        severity_counts = {
            Severity.CRITICAL: len([r for r in results if r.severity == Severity.CRITICAL and not r.compliant]),
            Severity.HIGH: len([r for r in results if r.severity == Severity.HIGH and not r.compliant]),
            Severity.MEDIUM: len([r for r in results if r.severity == Severity.MEDIUM and not r.compliant]),
            Severity.LOW: len([r for r in results if r.severity == Severity.LOW and not r.compliant]),
        }
        
        compliance_percentage = (compliant / total_findings * 100) if total_findings > 0 else 0
        
        # Summary text
        summary_text = f"""
        This security assessment evaluated {total_findings} security parameters on the target system. 
        The overall compliance rate is {compliance_percentage:.1f}%, with {non_compliant} findings 
        requiring attention.
        
        Critical security issues requiring immediate attention: {severity_counts[Severity.CRITICAL]}
        High priority security issues: {severity_counts[Severity.HIGH]}
        Medium priority security issues: {severity_counts[Severity.MEDIUM]}
        Low priority security issues: {severity_counts[Severity.LOW]}
        
        This report provides detailed analysis of each finding along with specific remediation 
        recommendations to improve the security posture of the system.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary statistics table
        summary_data = [
            ["Metric", "Count", "Percentage"],
            ["Total Parameters Assessed", str(total_findings), "100%"],
            ["Compliant Parameters", str(compliant), f"{compliance_percentage:.1f}%"],
            ["Non-Compliant Parameters", str(non_compliant), f"{100-compliance_percentage:.1f}%"],
            ["Critical Findings", str(severity_counts[Severity.CRITICAL]), f"{severity_counts[Severity.CRITICAL]/total_findings*100:.1f}%" if total_findings > 0 else "0%"],
            ["High Priority Findings", str(severity_counts[Severity.HIGH]), f"{severity_counts[Severity.HIGH]/total_findings*100:.1f}%" if total_findings > 0 else "0%"],
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 1*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        
        return story
    
    def _create_assessment_overview(self, results: List[AssessmentResult]) -> List:
        """Create assessment overview with charts."""
        story = []
        
        story.append(Paragraph("Assessment Overview", self.styles['CustomSubtitle']))
        
        # Create severity distribution pie chart
        severity_chart = self._create_severity_pie_chart(results)
        story.append(severity_chart)
        story.append(Spacer(1, 0.3*inch))
        
        # Create compliance bar chart
        compliance_chart = self._create_compliance_bar_chart(results)
        story.append(compliance_chart)
        
        return story
    
    def _create_severity_pie_chart(self, results: List[AssessmentResult]) -> Drawing:
        """Create pie chart showing severity distribution."""
        drawing = Drawing(400, 200)
        
        # Count findings by severity
        severity_counts = {
            'Critical': len([r for r in results if r.severity == Severity.CRITICAL and not r.compliant]),
            'High': len([r for r in results if r.severity == Severity.HIGH and not r.compliant]),
            'Medium': len([r for r in results if r.severity == Severity.MEDIUM and not r.compliant]),
            'Low': len([r for r in results if r.severity == Severity.LOW and not r.compliant]),
        }
        
        # Only include non-zero counts
        data = [(k, v) for k, v in severity_counts.items() if v > 0]
        
        if data:
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 100
            pie.height = 100
            pie.data = [item[1] for item in data]
            pie.labels = [f"{item[0]}: {item[1]}" for item in data]
            pie.slices.strokeColor = colors.white
            pie.slices.strokeWidth = 1
            
            # Color mapping
            color_map = {
                'Critical': colors.red,
                'High': colors.orange,
                'Medium': colors.yellow,
                'Low': colors.lightblue
            }
            
            for i, (label, _) in enumerate(data):
                severity_name = label.split(':')[0]
                pie.slices[i].fillColor = color_map.get(severity_name, colors.grey)
            
            drawing.add(pie)
        
        return drawing
    
    def _create_compliance_bar_chart(self, results: List[AssessmentResult]) -> Drawing:
        """Create bar chart showing compliance by category."""
        drawing = Drawing(400, 200)
        
        # Group results by category
        categories = {}
        for result in results:
            category = getattr(result, 'category', 'Unknown')
            if category not in categories:
                categories[category] = {'total': 0, 'compliant': 0}
            categories[category]['total'] += 1
            if result.compliant:
                categories[category]['compliant'] += 1
        
        if categories:
            chart = VerticalBarChart()
            chart.x = 50
            chart.y = 50
            chart.height = 125
            chart.width = 300
            
            # Prepare data
            category_names = list(categories.keys())[:6]  # Limit to 6 categories for readability
            compliance_rates = [
                (categories[cat]['compliant'] / categories[cat]['total'] * 100) 
                if categories[cat]['total'] > 0 else 0 
                for cat in category_names
            ]
            
            chart.data = [compliance_rates]
            chart.categoryAxis.categoryNames = category_names
            chart.valueAxis.valueMin = 0
            chart.valueAxis.valueMax = 100
            chart.bars[0].fillColor = colors.lightblue
            
            drawing.add(chart)
        
        return drawing
    
    def _create_detailed_findings(self, results: List[AssessmentResult]) -> List:
        """Create detailed findings section organized by severity."""
        story = []
        
        story.append(Paragraph("Detailed Security Findings", self.styles['CustomSubtitle']))
        
        # Group findings by severity
        findings_by_severity = {
            Severity.CRITICAL: [],
            Severity.HIGH: [],
            Severity.MEDIUM: [],
            Severity.LOW: []
        }
        
        for result in results:
            if not result.compliant:
                findings_by_severity[result.severity].append(result)
        
        # Create sections for each severity level
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = findings_by_severity[severity]
            if not findings:
                continue
            
            # Severity section header
            story.append(Paragraph(
                f"{severity.value.title()} Priority Findings ({len(findings)})",
                self.styles['SectionHeader']
            ))
            
            # Create table for findings
            table_data = [["Parameter", "Current Value", "Expected Value", "Risk Description"]]
            
            for finding in findings:
                table_data.append([
                    finding.parameter_id,
                    str(finding.current_value)[:50] + "..." if len(str(finding.current_value)) > 50 else str(finding.current_value),
                    str(finding.expected_value)[:50] + "..." if len(str(finding.expected_value)) > 50 else str(finding.expected_value),
                    finding.risk_description[:100] + "..." if len(finding.risk_description) > 100 else finding.risk_description
                ])
            
            findings_table = Table(table_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(findings_table)
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_remediation_section(self, results: List[AssessmentResult]) -> List:
        """Create remediation recommendations section."""
        story = []
        
        story.append(Paragraph("Remediation Recommendations", self.styles['CustomSubtitle']))
        
        # Group non-compliant results by severity for prioritized recommendations
        non_compliant = [r for r in results if not r.compliant]
        
        if not non_compliant:
            story.append(Paragraph("No remediation required. All assessed parameters are compliant.", self.styles['Normal']))
            return story
        
        # Priority-based recommendations
        story.append(Paragraph("Immediate Actions Required", self.styles['SectionHeader']))
        
        critical_high = [r for r in non_compliant if r.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        if critical_high:
            for i, result in enumerate(critical_high[:10], 1):  # Limit to top 10
                story.append(Paragraph(f"{i}. {result.parameter_id}", self.styles['Normal']))
                if result.remediation_steps:
                    for step in result.remediation_steps:
                        story.append(Paragraph(f"   • {step}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        else:
            story.append(Paragraph("No critical or high priority issues found.", self.styles['Normal']))
        
        return story
    
    def _create_hardening_summary(self, results: List[HardeningResult]) -> List:
        """Create executive summary for hardening reports."""
        story = []
        
        story.append(Paragraph("Hardening Operation Summary", self.styles['CustomSubtitle']))
        
        # Calculate statistics
        total_changes = len(results)
        successful_changes = len([r for r in results if r.success])
        failed_changes = total_changes - successful_changes
        success_rate = (successful_changes / total_changes * 100) if total_changes > 0 else 0
        
        # Summary text
        summary_text = f"""
        This hardening operation attempted to modify {total_changes} security parameters.
        {successful_changes} changes were applied successfully ({success_rate:.1f}% success rate).
        {failed_changes} changes failed and require manual intervention.
        
        All successful changes have been backed up and can be rolled back if necessary.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Statistics table
        stats_data = [
            ["Operation", "Count", "Percentage"],
            ["Total Parameters", str(total_changes), "100%"],
            ["Successful Changes", str(successful_changes), f"{success_rate:.1f}%"],
            ["Failed Changes", str(failed_changes), f"{100-success_rate:.1f}%"],
        ]
        
        stats_table = Table(stats_data, colWidths=[3*inch, 1*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(stats_table)
        
        return story
    
    def _create_before_after_analysis(self, results: List[HardeningResult]) -> List:
        """Create before/after comparison analysis."""
        story = []
        
        story.append(Paragraph("Before/After Analysis", self.styles['CustomSubtitle']))
        
        # Create table showing changes
        table_data = [["Parameter", "Previous Value", "Applied Value", "Status"]]
        
        for result in results:
            status = "✓ Success" if result.success else "✗ Failed"
            status_style = "Normal" if result.success else "Critical"
            
            table_data.append([
                result.parameter_id,
                str(result.previous_value)[:30] + "..." if len(str(result.previous_value)) > 30 else str(result.previous_value),
                str(result.applied_value)[:30] + "..." if len(str(result.applied_value)) > 30 else str(result.applied_value),
                status
            ])
        
        changes_table = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 1*inch])
        changes_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(changes_table)
        
        return story
    
    def _create_hardening_details(self, results: List[HardeningResult]) -> List:
        """Create detailed hardening results section."""
        story = []
        
        story.append(Paragraph("Detailed Hardening Results", self.styles['CustomSubtitle']))
        
        # Separate successful and failed changes
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        if successful:
            story.append(Paragraph(f"Successful Changes ({len(successful)})", self.styles['SectionHeader']))
            
            success_data = [["Parameter", "Previous Value", "New Value", "Timestamp"]]
            for result in successful:
                success_data.append([
                    result.parameter_id,
                    str(result.previous_value)[:40] + "..." if len(str(result.previous_value)) > 40 else str(result.previous_value),
                    str(result.applied_value)[:40] + "..." if len(str(result.applied_value)) > 40 else str(result.applied_value),
                    result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                ])
            
            success_table = Table(success_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            success_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgreen),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(success_table)
            story.append(Spacer(1, 0.2*inch))
        
        if failed:
            story.append(Paragraph(f"Failed Changes ({len(failed)})", self.styles['SectionHeader']))
            
            failed_data = [["Parameter", "Attempted Value", "Error Message", "Timestamp"]]
            for result in failed:
                failed_data.append([
                    result.parameter_id,
                    str(result.applied_value)[:40] + "..." if len(str(result.applied_value)) > 40 else str(result.applied_value),
                    result.error_message[:60] + "..." if result.error_message and len(result.error_message) > 60 else (result.error_message or "Unknown error"),
                    result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                ])
            
            failed_table = Table(failed_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
            failed_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(failed_table)
        
        return story
    
    def _create_rollback_section(self, results: List[HardeningResult]) -> List:
        """Create rollback information section."""
        story = []
        
        story.append(Paragraph("Rollback Information", self.styles['CustomSubtitle']))
        
        backed_up = [r for r in results if r.backup_created and r.success]
        
        if backed_up:
            rollback_text = f"""
            {len(backed_up)} parameters have been successfully backed up and can be rolled back if needed.
            Use the rollback functionality to restore previous values if any issues are encountered.
            
            Backup created at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            """
            story.append(Paragraph(rollback_text, self.styles['Normal']))
        else:
            story.append(Paragraph("No backup data available for rollback.", self.styles['Normal']))
        
        return story
    
    def _create_compliance_summary(self, results: List[AssessmentResult], framework: ComplianceFramework) -> List:
        """Create compliance framework summary."""
        story = []
        
        story.append(Paragraph(f"{framework.value} Compliance Summary", self.styles['CustomSubtitle']))
        
        # Calculate framework-specific compliance using the mapper
        compliance_data = self.compliance_mapper.calculate_framework_compliance(results, framework)
        
        summary_text = f"""
        This {framework.value} compliance assessment evaluated {compliance_data['total_controls']} framework controls.
        Current compliance rate: {compliance_data['compliance_percentage']:.1f}%
        
        Compliant controls: {compliance_data['compliant_controls']}
        Non-compliant controls: {compliance_data['total_controls'] - compliance_data['compliant_controls']}
        
        This report provides detailed analysis aligned with {framework.value} framework requirements
        and specific recommendations to achieve full compliance.
        """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        
        return story
    
    def _create_framework_analysis(self, results: List[AssessmentResult], framework: ComplianceFramework) -> List:
        """Create framework-specific analysis section."""
        story = []
        
        story.append(Paragraph(f"{framework.value} Control Analysis", self.styles['CustomSubtitle']))
        
        # Get framework categories and analyze compliance by category
        categories = self.compliance_mapper.get_framework_categories(framework)
        
        if not categories:
            story.append(Paragraph(f"No controls defined for {framework.value} framework.", self.styles['Normal']))
            return story
        
        # Compliance table by category
        compliance_data = [
            ["Control Category", "Total Controls", "Assessed Parameters", "Compliant Parameters", "Compliance %"]
        ]
        
        for category in categories:
            category_controls = self.compliance_mapper.get_controls_by_category(framework, category)
            total_controls = len(category_controls)
            
            # Count assessed and compliant parameters for this category
            assessed_params = 0
            compliant_params = 0
            
            for control in category_controls:
                for param_id in control.parameter_mappings:
                    matching_results = [r for r in results if r.parameter_id == param_id]
                    if matching_results:
                        assessed_params += len(matching_results)
                        compliant_params += len([r for r in matching_results if r.compliant])
            
            compliance_rate = (compliant_params / assessed_params * 100) if assessed_params > 0 else 0
            
            compliance_data.append([
                category,
                str(total_controls),
                str(assessed_params),
                str(compliant_params),
                f"{compliance_rate:.1f}%" if assessed_params > 0 else "N/A"
            ])
        
        compliance_table = Table(compliance_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 1*inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(compliance_table)
        
        return story
    
    def _create_gap_analysis(self, results: List[AssessmentResult], framework: ComplianceFramework) -> List:
        """Create gap analysis and recommendations."""
        story = []
        
        story.append(Paragraph("Gap Analysis and Recommendations", self.styles['CustomSubtitle']))
        
        # Use compliance mapper to identify gaps
        gaps = self.compliance_mapper.identify_compliance_gaps(results, framework)
        
        if not gaps:
            story.append(Paragraph(f"Congratulations! Full compliance with {framework.value} framework achieved.", self.styles['Normal']))
            return story
        
        # Priority recommendations based on severity
        story.append(Paragraph("Priority Recommendations", self.styles['SectionHeader']))
        
        # Group gaps by severity
        critical_gaps = [g for g in gaps if g.priority == Severity.CRITICAL]
        high_gaps = [g for g in gaps if g.priority == Severity.HIGH]
        medium_gaps = [g for g in gaps if g.priority == Severity.MEDIUM]
        
        if critical_gaps:
            story.append(Paragraph("Critical Gaps (Immediate Action Required):", self.styles['Normal']))
            for gap in critical_gaps[:5]:  # Top 5 critical
                story.append(Paragraph(f"• {gap.control_id} - {gap.control_title} ({gap.current_compliance:.1f}% compliant)", self.styles['Critical']))
                if gap.recommendations:
                    for rec in gap.recommendations[:2]:  # Top 2 recommendations
                        story.append(Paragraph(f"  - {rec}", self.styles['Normal']))
        
        if high_gaps:
            story.append(Paragraph("High Priority Gaps:", self.styles['Normal']))
            for gap in high_gaps[:5]:  # Top 5 high
                story.append(Paragraph(f"• {gap.control_id} - {gap.control_title} ({gap.current_compliance:.1f}% compliant)", self.styles['High']))
                if gap.recommendations:
                    for rec in gap.recommendations[:2]:  # Top 2 recommendations
                        story.append(Paragraph(f"  - {rec}", self.styles['Normal']))
        
        if medium_gaps:
            story.append(Paragraph("Medium Priority Gaps:", self.styles['Normal']))
            for gap in medium_gaps[:3]:  # Top 3 medium
                story.append(Paragraph(f"• {gap.control_id} - {gap.control_title} ({gap.current_compliance:.1f}% compliant)", self.styles['Medium']))
        
        return story
    
    def _create_compliance_matrix(self, results: List[AssessmentResult], framework: ComplianceFramework) -> List:
        """Create compliance matrix showing parameter to control mappings."""
        story = []
        
        story.append(Paragraph("Compliance Matrix", self.styles['CustomSubtitle']))
        
        # Generate compliance matrix
        matrix = self.compliance_mapper.generate_compliance_matrix(results, framework)
        
        if not matrix:
            story.append(Paragraph("No parameter mappings found for this framework.", self.styles['Normal']))
            return story
        
        # Create table showing parameter to control mappings
        matrix_data = [["Parameter", "Compliance Status", "Mapped Controls", "Control Categories"]]
        
        for param_id, param_data in matrix.items():
            compliance_status = "✓ Compliant" if param_data['compliant'] else "✗ Non-Compliant"
            
            # Get control information
            controls = param_data['mapped_controls']
            control_ids = [c['control_id'] for c in controls]
            categories = list(set([c['category'] for c in controls]))
            
            matrix_data.append([
                param_id,
                compliance_status,
                ', '.join(control_ids[:3]) + ('...' if len(control_ids) > 3 else ''),
                ', '.join(categories[:2]) + ('...' if len(categories) > 2 else '')
            ])
        
        matrix_table = Table(matrix_data, colWidths=[2*inch, 1*inch, 2*inch, 1.5*inch])
        matrix_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(matrix_table)
        
        return story