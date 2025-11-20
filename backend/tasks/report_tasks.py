"""
Report Generation Tasks
Generates PDF and HTML reports with compliance mappings
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from celery_config import celery_app
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from jinja2 import Template
import os

logger = logging.getLogger(__name__)

# Try PostgreSQL first
try:
    from database.connection import get_scan_by_id, create_report, get_db_cursor
    USE_POSTGRES = True
except:
    from utils.database import get_db_connection
    USE_POSTGRES = False

PDF_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { background: #ecf0f1; padding: 15px; border-left: 4px solid #3498db; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; font-weight: bold; }
        .low { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #34495e; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        .compliance { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>{{report_title}}</h1>
    <div class="summary">
        <p><strong>Report Generated:</strong> {{generated_date}}</p>
        <p><strong>Target:</strong> {{target}}</p>
        <p><strong>Scan Type:</strong> {{scan_type}}</p>
        <p><strong>Overall Risk Level:</strong> <span class="{{risk_level}}">{{risk_level|upper}}</span></p>
    </div>

    <h2>Executive Summary</h2>
    <p>{{executive_summary}}</p>

    <h2>Vulnerabilities Found</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Description</th>
            <th>Remediation</th>
        </tr>
        {% for vuln in vulnerabilities %}
        <tr>
            <td class="{{vuln.severity}}">{{vuln.severity|upper}}</td>
            <td>{{vuln.description}}</td>
            <td>{{vuln.remediation}}</td>
        </tr>
        {% endfor %}
    </table>

    {% if compliance_mappings %}
    <h2>Compliance Impact</h2>
    {% for framework, requirements in compliance_mappings.items() %}
    <div class="compliance">
        <h3>{{framework}}</h3>
        <ul>
        {% for req in requirements %}
            <li>{{req}}</li>
        {% endfor %}
        </ul>
    </div>
    {% endfor %}
    {% endif %}

    <h2>Recommendations</h2>
    <ol>
        {% for recommendation in recommendations %}
        <li>{{recommendation}}</li>
        {% endfor %}
    </ol>
</body>
</html>
"""

@celery_app.task(name='tasks.report_tasks.generate_pdf_report')
def generate_pdf_report(
    scan_id: int,
    report_name: str = "Security Assessment",
    include_compliance: bool = True,
    compliance_frameworks: List[str] = None
):
    """
    Generate PDF report for a scan
    
    Args:
        scan_id: Scan ID to generate report for
        report_name: Name of the report
        include_compliance: Include compliance mappings
        compliance_frameworks: Specific frameworks to check
    """
    logger.info(f"Generating PDF report for scan {scan_id}")
    
    try:
        # Get scan data
        if USE_POSTGRES:
            scan = get_scan_by_id(scan_id)
        else:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scan_results WHERE id = ?", (scan_id,))
                scan = dict(cursor.fetchone())
        
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Parse results
        results = json.loads(scan.get('results', scan.get('raw_output', '{}')))
        
        # Create report directory
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_dir}/report_{scan_id}_{timestamp}.pdf"
        
        # Create PDF
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
        )
        story.append(Paragraph(report_name, title_style))
        story.append(Spacer(1, 12))
        
        # Summary
        summary_data = [
            ['Report Generated:', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ['Target:', scan.get('target', 'Unknown')],
            ['Scan Type:', scan.get('scan_type', scan.get('tool', 'Unknown'))],
            ['Status:', scan.get('status', 'Unknown')],
            ['Risk Level:', scan.get('risk_level', 'Unknown').upper()]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = scan.get('summary', 'No summary available')
        story.append(Paragraph(summary_text, styles['BodyText']))
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        story.append(Paragraph("Findings", styles['Heading2']))
        vulnerabilities = extract_vulnerabilities(results, scan.get('scan_type', scan.get('tool')))
        
        if vulnerabilities:
            vuln_data = [['Severity', 'Description', 'Recommendation']]
            for vuln in vulnerabilities[:20]:  # Limit to top 20
                vuln_data.append([
                    vuln.get('severity', 'Unknown').upper(),
                    vuln.get('description', 'N/A')[:100],
                    vuln.get('remediation', 'N/A')[:100]
                ])
            
            vuln_table = Table(vuln_data, colWidths=[1*inch, 2.5*inch, 2.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No vulnerabilities found", styles['BodyText']))
        
        story.append(Spacer(1, 20))
        
        # Compliance (if requested)
        if include_compliance and compliance_frameworks:
            story.append(PageBreak())
            story.append(Paragraph("Compliance Assessment", styles['Heading2']))
            
            compliance_text = f"Assessed against: {', '.join(compliance_frameworks)}"
            story.append(Paragraph(compliance_text, styles['BodyText']))
            story.append(Spacer(1, 12))
            
            # Add compliance details
            story.append(Paragraph("Affected Standards:", styles['Heading3']))
            for framework in compliance_frameworks:
                story.append(Paragraph(f"• {framework}", styles['BodyText']))
        
        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("Recommendations", styles['Heading2']))
        recommendations = generate_recommendations(vulnerabilities, scan.get('scan_type'))
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['BodyText']))
            story.append(Spacer(1, 8))
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {filename}")
        
        # Store report record
        if USE_POSTGRES:
            report = create_report(
                user_id=scan.get('user_id'),
                scan_id=scan_id,
                report_name=report_name,
                report_type='pentest',
                format='pdf',
                compliance_frameworks=json.dumps(compliance_frameworks) if compliance_frameworks else None
            )
            
            # Update with file location
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE reports SET file_url = %s, status = 'completed'
                    WHERE id = %s
                """, (filename, report['id']))
        
        return {
            "success": True,
            "filename": filename,
            "scan_id": scan_id
        }
        
    except Exception as e:
        logger.error(f"PDF report generation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }

@celery_app.task(name='tasks.report_tasks.generate_html_report')
def generate_html_report(
    scan_id: int,
    report_name: str = "Security Assessment",
    include_compliance: bool = True,
    compliance_frameworks: List[str] = None
):
    """Generate HTML report for a scan"""
    logger.info(f"Generating HTML report for scan {scan_id}")
    
    try:
        # Get scan data
        if USE_POSTGRES:
            scan = get_scan_by_id(scan_id)
        else:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scan_results WHERE id = ?", (scan_id,))
                scan = dict(cursor.fetchone())
        
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Parse results
        results = json.loads(scan.get('results', scan.get('raw_output', '{}')))
        vulnerabilities = extract_vulnerabilities(results, scan.get('scan_type', scan.get('tool')))
        recommendations = generate_recommendations(vulnerabilities, scan.get('scan_type'))
        
        # Prepare template data
        template_data = {
            'report_title': report_name,
            'generated_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'target': scan.get('target', 'Unknown'),
            'scan_type': scan.get('scan_type', scan.get('tool', 'Unknown')),
            'risk_level': scan.get('risk_level', 'unknown'),
            'executive_summary': scan.get('summary', 'No summary available'),
            'vulnerabilities': vulnerabilities,
            'recommendations': recommendations,
            'compliance_mappings': {} if not include_compliance else {
                framework: [f"Requirement affected"] for framework in (compliance_frameworks or [])
            }
        }
        
        # Render template
        template = Template(PDF_TEMPLATE)
        html_content = template.render(**template_data)
        
        # Save HTML
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_dir}/report_{scan_id}_{timestamp}.html"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filename}")
        
        return {
            "success": True,
            "filename": filename,
            "scan_id": scan_id
        }
        
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def extract_vulnerabilities(results: Dict, scan_type: str) -> List[Dict]:
    """Extract vulnerabilities from scan results"""
    vulnerabilities = []
    
    if scan_type == 'port_scan':
        for port_info in results.get('open_ports', []):
            vulnerabilities.append({
                'severity': 'medium' if port_info['port'] in [21, 23, 445] else 'low',
                'description': f"Port {port_info['port']} ({port_info['service']}) is open",
                'remediation': f"Review if port {port_info['port']} needs to be exposed"
            })
    
    elif scan_type == 'web_scan':
        for vuln in results.get('vulnerabilities', []):
            vulnerabilities.append({
                'severity': vuln.get('severity', 'medium'),
                'description': vuln.get('title', 'Unknown vulnerability'),
                'remediation': vuln.get('remediation', 'Review and fix')
            })
    
    return vulnerabilities

def generate_recommendations(vulnerabilities: List[Dict], scan_type: str) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    if not vulnerabilities:
        return ["No immediate action required. Continue monitoring."]
    
    # Count by severity
    critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
    high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
    medium = sum(1 for v in vulnerabilities if v.get('severity') == 'medium')
    
    if critical > 0:
        recommendations.append(f"URGENT: Address {critical} critical vulnerability(ies) immediately")
    
    if high > 0:
        recommendations.append(f"High Priority: Fix {high} high-severity issue(s) within 7 days")
    
    if medium > 0:
        recommendations.append(f"Medium Priority: Address {medium} medium-severity issue(s) within 30 days")
    
    # General recommendations
    recommendations.extend([
        "Conduct regular security assessments (monthly recommended)",
        "Implement continuous monitoring for new vulnerabilities",
        "Ensure all software is up-to-date with latest security patches",
        "Review and update security policies and procedures",
        "Provide security awareness training to relevant personnel"
    ])
    
    return recommendations
