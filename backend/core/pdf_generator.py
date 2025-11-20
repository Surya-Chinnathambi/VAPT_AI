"""
PDF Report Generator
Week 9-10: Professional PDF generation for vulnerability reports

Features:
- Executive summary reports
- Technical vulnerability reports
- Compliance reports
- Charts and visualizations
- Custom branding
"""
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import io
import base64

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart


logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """Generate professional PDF reports"""
    
    def __init__(self, page_size=letter):
        """Initialize PDF generator"""
        self.page_size = page_size
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        logger.info("PDF Report Generator initialized")
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['BodyText'],
            fontSize=11,
            leading=16,
            alignment=TA_JUSTIFY,
            spaceAfter=12
        ))
        
        # CVE style
        self.styles.add(ParagraphStyle(
            name='CVETitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#d32f2f'),
            fontName='Helvetica-Bold',
            spaceAfter=6
        ))
    
    def generate_vulnerability_report(
        self,
        scan_data: Dict[str, Any],
        cves: List[Dict],
        exploits: List[Dict],
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generate comprehensive vulnerability report
        
        Args:
            scan_data: Scan results with target, ports, services
            cves: List of discovered CVEs
            exploits: List of available exploits
            output_path: Optional path to save PDF
            
        Returns:
            PDF bytes
        """
        logger.info(f"Generating vulnerability report for {scan_data.get('target', 'unknown')}")
        
        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=self.page_size,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build content
        story = []
        
        # Cover page
        story.extend(self._create_cover_page(scan_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(scan_data, cves, exploits))
        story.append(PageBreak())
        
        # Vulnerability details
        story.extend(self._create_vulnerability_section(cves, exploits))
        
        # Recommendations
        story.append(PageBreak())
        story.extend(self._create_recommendations_section(cves))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        
        # Get PDF bytes
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        # Save if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
            logger.info(f"Report saved to {output_path}")
        
        return pdf_bytes
    
    def _create_cover_page(self, scan_data: Dict) -> List:
        """Create cover page"""
        story = []
        
        # Title
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("Cybersecurity Assessment Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Target info
        target = scan_data.get('target', 'Unknown Target')
        story.append(Paragraph(f"<b>Target:</b> {target}", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Date
        scan_date = scan_data.get('timestamp', datetime.now().isoformat())
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Classification
        story.append(Spacer(1, inch))
        story.append(Paragraph(
            "<b>Classification: CONFIDENTIAL</b>",
            self.styles['Normal']
        ))
        
        return story
    
    def _create_executive_summary(
        self,
        scan_data: Dict,
        cves: List[Dict],
        exploits: List[Dict]
    ) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 0.2*inch))
        
        # Statistics
        critical_count = sum(1 for cve in cves if cve.get('severity') == 'CRITICAL')
        high_count = sum(1 for cve in cves if cve.get('severity') == 'HIGH')
        medium_count = sum(1 for cve in cves if cve.get('severity') == 'MEDIUM')
        low_count = sum(1 for cve in cves if cve.get('severity') == 'LOW')
        
        summary_text = f"""
        This report presents the findings of a comprehensive security assessment conducted on 
        {scan_data.get('target', 'the target system')}. The assessment identified a total of 
        <b>{len(cves)} vulnerabilities</b>, including {critical_count} critical, {high_count} high, 
        {medium_count} medium, and {low_count} low severity issues.
        """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.3*inch))
        
        # Severity chart
        if cves:
            story.append(self._create_severity_chart(critical_count, high_count, medium_count, low_count))
            story.append(Spacer(1, 0.3*inch))
        
        # Summary table
        summary_data = [
            ['Metric', 'Value'],
            ['Total Vulnerabilities', str(len(cves))],
            ['Critical Severity', str(critical_count)],
            ['High Severity', str(high_count)],
            ['Available Exploits', str(len(exploits))],
            ['Open Ports', str(len(scan_data.get('open_ports', [])))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        
        return story
    
    def _create_severity_chart(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int
    ) -> Drawing:
        """Create pie chart for severity distribution"""
        drawing = Drawing(400, 200)
        
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        
        pie.data = [critical, high, medium, low]
        pie.labels = ['Critical', 'High', 'Medium', 'Low']
        pie.slices.strokeWidth = 0.5
        
        # Colors
        pie.slices[0].fillColor = colors.HexColor('#d32f2f')  # Critical - Red
        pie.slices[1].fillColor = colors.HexColor('#f57c00')  # High - Orange
        pie.slices[2].fillColor = colors.HexColor('#fbc02d')  # Medium - Yellow
        pie.slices[3].fillColor = colors.HexColor('#388e3c')  # Low - Green
        
        drawing.add(pie)
        
        return drawing
    
    def _create_vulnerability_section(
        self,
        cves: List[Dict],
        exploits: List[Dict]
    ) -> List:
        """Create vulnerability details section"""
        story = []
        
        story.append(Paragraph("Vulnerability Details", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 0.2*inch))
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        sorted_cves = sorted(
            cves,
            key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 4)
        )
        
        for cve in sorted_cves:
            story.extend(self._create_cve_entry(cve, exploits))
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_cve_entry(self, cve: Dict, exploits: List[Dict]) -> List:
        """Create single CVE entry"""
        story = []
        
        cve_id = cve.get('cve_id', cve.get('id', 'Unknown'))
        severity = cve.get('severity', 'UNKNOWN')
        cvss = cve.get('cvss_score', 'N/A')
        
        # CVE title with severity color
        severity_colors = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f57c00',
            'MEDIUM': '#fbc02d',
            'LOW': '#388e3c'
        }
        color = severity_colors.get(severity, '#666666')
        
        title_text = f'<font color="{color}"><b>{cve_id}</b></font> - Severity: {severity} (CVSS: {cvss})'
        story.append(Paragraph(title_text, self.styles['Heading4']))
        
        # Description
        description = cve.get('description', 'No description available')
        story.append(Paragraph(f"<b>Description:</b> {description[:500]}", self.styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
        
        # Find related exploits
        related_exploits = [e for e in exploits if cve_id in e.get('description', '')]
        if related_exploits:
            story.append(Paragraph(
                f"<b>⚠️ {len(related_exploits)} exploit(s) available</b>",
                self.styles['Normal']
            ))
        
        return story
    
    def _create_recommendations_section(self, cves: List[Dict]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = [
            "Prioritize patching of CRITICAL and HIGH severity vulnerabilities immediately",
            "Implement network segmentation to limit exposure of vulnerable services",
            "Deploy intrusion detection/prevention systems (IDS/IPS)",
            "Conduct regular security assessments and penetration testing",
            "Maintain an up-to-date vulnerability management program",
            "Implement multi-factor authentication (MFA) for all critical systems",
            "Regular security awareness training for all staff members"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _add_page_number(self, canvas, doc):
        """Add page number to footer"""
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(
            self.page_size[0] - 72,
            0.5*inch,
            text
        )
        canvas.restoreState()
    
    def generate_compliance_report(
        self,
        vulnerabilities: List[Dict],
        framework: str,
        compliance_mapping: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generate compliance report (NIST, ISO 27001, PCI-DSS, etc.)
        
        Args:
            vulnerabilities: List of vulnerabilities
            framework: Compliance framework name
            compliance_mapping: Mapping of vulnerabilities to controls
            output_path: Optional save path
            
        Returns:
            PDF bytes
        """
        logger.info(f"Generating {framework} compliance report")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=self.page_size)
        
        story = []
        
        # Title
        story.append(Paragraph(
            f"{framework} Compliance Report",
            self.styles['CustomTitle']
        ))
        story.append(Spacer(1, 0.5*inch))
        
        # Compliance summary
        total_controls = len(compliance_mapping.get('controls', []))
        failed_controls = len(compliance_mapping.get('failed_controls', []))
        compliance_rate = ((total_controls - failed_controls) / total_controls * 100) if total_controls > 0 else 0
        
        summary_text = f"""
        This report assesses compliance with {framework} security controls based on the 
        identified vulnerabilities. Current compliance rate: <b>{compliance_rate:.1f}%</b>
        """
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.3*inch))
        
        # Gap analysis table
        story.append(Paragraph("Gap Analysis", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 0.2*inch))
        
        gap_data = [['Control ID', 'Control Name', 'Status', 'Findings']]
        
        for control in compliance_mapping.get('failed_controls', [])[:10]:
            gap_data.append([
                control.get('id', ''),
                control.get('name', '')[:40],
                'Failed',
                str(control.get('finding_count', 0))
            ])
        
        gap_table = Table(gap_data, colWidths=[1*inch, 3*inch, 1*inch, 1*inch])
        gap_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        
        story.append(gap_table)
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
        
        return pdf_bytes


# Global singleton
_pdf_generator: Optional[PDFReportGenerator] = None


def get_pdf_generator() -> PDFReportGenerator:
    """Get PDF generator singleton"""
    global _pdf_generator
    if _pdf_generator is None:
        _pdf_generator = PDFReportGenerator()
    return _pdf_generator
