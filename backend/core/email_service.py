"""
Email Service
Week 9-10: Send security reports via email

Features:
- SMTP integration with async support
- Email templates with Jinja2
- PDF attachment handling
- Scheduled report delivery
- Email queue with Celery
"""
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape
from email_validator import validate_email, EmailNotValidError


logger = logging.getLogger(__name__)


class EmailService:
    """Email service for sending security reports"""
    
    def __init__(self):
        """Initialize email service"""
        self.smtp_host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_user = os.getenv('SMTP_USER', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.from_email = os.getenv('FROM_EMAIL', self.smtp_user)
        self.from_name = os.getenv('FROM_NAME', 'CyberShield AI Security')
        
        # Setup Jinja2 for email templates
        template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates', 'email')
        os.makedirs(template_dir, exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        logger.info(f"Email service initialized with SMTP: {self.smtp_host}:{self.smtp_port}")
    
    def validate_email_address(self, email: str) -> bool:
        """
        Validate email address
        
        Args:
            email: Email address to validate
            
        Returns:
            True if valid
        """
        try:
            validate_email(email)
            return True
        except EmailNotValidError as e:
            logger.warning(f"Invalid email {email}: {e}")
            return False
    
    async def send_email(
        self,
        to_emails: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
        cc_emails: Optional[List[str]] = None,
        bcc_emails: Optional[List[str]] = None
    ) -> bool:
        """
        Send email with optional attachments
        
        Args:
            to_emails: List of recipient email addresses
            subject: Email subject
            body_text: Plain text body
            body_html: HTML body (optional)
            attachments: List of attachments [{'filename': '', 'content': bytes}]
            cc_emails: CC recipients
            bcc_emails: BCC recipients
            
        Returns:
            True if sent successfully
        """
        try:
            # Validate recipients
            valid_to = [e for e in to_emails if self.validate_email_address(e)]
            if not valid_to:
                logger.error("No valid recipient email addresses")
                return False
            
            # Create message
            message = MIMEMultipart('alternative')
            message['From'] = f"{self.from_name} <{self.from_email}>"
            message['To'] = ', '.join(valid_to)
            message['Subject'] = subject
            message['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
            
            if cc_emails:
                valid_cc = [e for e in cc_emails if self.validate_email_address(e)]
                if valid_cc:
                    message['Cc'] = ', '.join(valid_cc)
            
            # Add plain text body
            text_part = MIMEText(body_text, 'plain', 'utf-8')
            message.attach(text_part)
            
            # Add HTML body if provided
            if body_html:
                html_part = MIMEText(body_html, 'html', 'utf-8')
                message.attach(html_part)
            
            # Add attachments
            if attachments:
                for attachment in attachments:
                    filename = attachment.get('filename', 'attachment.pdf')
                    content = attachment.get('content', b'')
                    
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(content)
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {filename}'
                    )
                    message.attach(part)
            
            # Send email
            all_recipients = valid_to.copy()
            if cc_emails:
                all_recipients.extend([e for e in cc_emails if self.validate_email_address(e)])
            if bcc_emails:
                all_recipients.extend([e for e in bcc_emails if self.validate_email_address(e)])
            
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            
            logger.info(f"Email sent to {len(valid_to)} recipient(s): {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def send_vulnerability_report(
        self,
        to_emails: List[str],
        scan_data: Dict[str, Any],
        report_pdf: bytes,
        report_filename: str = "vulnerability_report.pdf"
    ) -> bool:
        """
        Send vulnerability report email
        
        Args:
            to_emails: Recipients
            scan_data: Scan metadata
            report_pdf: PDF report bytes
            report_filename: PDF filename
            
        Returns:
            True if sent successfully
        """
        target = scan_data.get('target', 'Unknown Target')
        scan_date = scan_data.get('timestamp', datetime.now().isoformat())
        vuln_count = scan_data.get('vulnerability_count', 0)
        critical_count = scan_data.get('critical_count', 0)
        
        # Plain text body
        body_text = f"""
CyberShield AI Security Report

Target: {target}
Scan Date: {scan_date}
Total Vulnerabilities: {vuln_count}
Critical Vulnerabilities: {critical_count}

Please find the detailed security assessment report attached.

This is an automated message from CyberShield AI Security Platform.
        """.strip()
        
        # HTML body
        body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background-color: #1976d2; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .stats {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .footer {{ background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CyberShield AI Security Report</h1>
    </div>
    <div class="content">
        <h2>Security Assessment Complete</h2>
        <p>A comprehensive security assessment has been completed for <strong>{target}</strong>.</p>
        
        <div class="stats">
            <h3>Summary Statistics</h3>
            <ul>
                <li><strong>Target:</strong> {target}</li>
                <li><strong>Scan Date:</strong> {scan_date}</li>
                <li><strong>Total Vulnerabilities:</strong> {vuln_count}</li>
                <li class="critical"><strong>Critical Vulnerabilities:</strong> {critical_count}</li>
            </ul>
        </div>
        
        <p>Please review the attached PDF report for detailed findings and remediation recommendations.</p>
        
        <p><strong>⚠️ Action Required:</strong> Critical vulnerabilities require immediate attention.</p>
    </div>
    <div class="footer">
        <p>This is an automated message from CyberShield AI Security Platform.</p>
        <p>© 2025 CyberShield AI. All rights reserved.</p>
    </div>
</body>
</html>
        """.strip()
        
        # Send with PDF attachment
        return await self.send_email(
            to_emails=to_emails,
            subject=f"Security Report: {target} - {vuln_count} Vulnerabilities Found",
            body_text=body_text,
            body_html=body_html,
            attachments=[{
                'filename': report_filename,
                'content': report_pdf
            }]
        )
    
    async def send_compliance_report(
        self,
        to_emails: List[str],
        framework: str,
        compliance_rate: float,
        report_pdf: bytes,
        report_filename: str = "compliance_report.pdf"
    ) -> bool:
        """
        Send compliance report email
        
        Args:
            to_emails: Recipients
            framework: Compliance framework name
            compliance_rate: Compliance percentage
            report_pdf: PDF report bytes
            report_filename: PDF filename
            
        Returns:
            True if sent successfully
        """
        status = "COMPLIANT" if compliance_rate >= 95 else "NON-COMPLIANT"
        status_color = "#388e3c" if compliance_rate >= 95 else "#d32f2f"
        
        body_text = f"""
CyberShield AI Compliance Report

Framework: {framework}
Compliance Rate: {compliance_rate:.1f}%
Status: {status}

Please find the detailed compliance assessment report attached.

This is an automated message from CyberShield AI Security Platform.
        """.strip()
        
        body_html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .header {{ background-color: #1976d2; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .compliance-badge {{ background-color: {status_color}; color: white; padding: 10px 20px; 
                           border-radius: 5px; display: inline-block; margin: 20px 0; font-weight: bold; }}
        .footer {{ background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 Compliance Assessment Report</h1>
    </div>
    <div class="content">
        <h2>{framework} Compliance Assessment</h2>
        
        <div class="compliance-badge">
            {status} - {compliance_rate:.1f}%
        </div>
        
        <p>A comprehensive compliance assessment has been completed against the <strong>{framework}</strong> framework.</p>
        
        <p>Please review the attached PDF report for detailed gap analysis and remediation recommendations.</p>
    </div>
    <div class="footer">
        <p>This is an automated message from CyberShield AI Security Platform.</p>
        <p>© 2025 CyberShield AI. All rights reserved.</p>
    </div>
</body>
</html>
        """.strip()
        
        return await self.send_email(
            to_emails=to_emails,
            subject=f"{framework} Compliance Report - {compliance_rate:.1f}% Compliant",
            body_text=body_text,
            body_html=body_html,
            attachments=[{
                'filename': report_filename,
                'content': report_pdf
            }]
        )
    
    async def send_scheduled_report(
        self,
        to_emails: List[str],
        report_type: str,
        report_pdf: bytes,
        metadata: Dict[str, Any]
    ) -> bool:
        """
        Send scheduled security report
        
        Args:
            to_emails: Recipients
            report_type: Type of report (weekly, monthly, etc.)
            report_pdf: PDF bytes
            metadata: Report metadata
            
        Returns:
            True if sent successfully
        """
        subject = f"{report_type.title()} Security Report - {datetime.now().strftime('%B %Y')}"
        filename = f"{report_type}_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        body_text = f"""
{report_type.title()} Security Report

This is your scheduled {report_type} security summary.

Report Period: {metadata.get('period', 'N/A')}
Total Scans: {metadata.get('total_scans', 0)}
Vulnerabilities Found: {metadata.get('total_vulnerabilities', 0)}

Please find the detailed report attached.

This is an automated message from CyberShield AI Security Platform.
        """.strip()
        
        return await self.send_email(
            to_emails=to_emails,
            subject=subject,
            body_text=body_text,
            attachments=[{
                'filename': filename,
                'content': report_pdf
            }]
        )


# Global singleton
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get email service singleton"""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
