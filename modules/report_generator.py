import json
import csv
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from urllib.parse import urlparse

class ReportGenerator:
    def __init__(self):
        pass
    
    def generate_json_report(self, results):
        """Generate a JSON report of all findings"""
        report = {
            'scan_metadata': {
                'target': results.get('target', 'Unknown'),
                'timestamp': results.get('timestamp', datetime.now().isoformat()),
                'tool': 'WebRecon Security Scanner',
                'version': '1.0'
            },
            'summary': self._generate_summary(results['findings']),
            'findings': results['findings']
        }
        
        return json.dumps(report, indent=2)
    
    def generate_csv_report(self, results):
        """Generate a CSV report of all findings"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Title', 'Severity', 'Description', 'Details', 'Category'])
        
        # Write findings
        for finding in results['findings']:
            writer.writerow([
                finding.get('title', ''),
                finding.get('severity', ''),
                finding.get('description', ''),
                finding.get('details', ''),
                self._categorize_finding(finding)
            ])
        
        return output.getvalue()
    
    def generate_html_report(self, results):
        """Generate an HTML report of all findings"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebRecon Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
                .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
                .high { background-color: #ffebee; border-left-color: #f44336; }
                .medium { background-color: #fff8e1; border-left-color: #ff9800; }
                .low { background-color: #e8f5e8; border-left-color: #4caf50; }
                .info { background-color: #e3f2fd; border-left-color: #2196f3; }
                .severity { font-weight: bold; text-transform: uppercase; }
                .title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
                .description { margin-bottom: 10px; }
                .details { font-size: 14px; color: #666; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WebRecon Security Assessment Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {timestamp}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Findings: {total_findings}</p>
                <p>High Severity: {high_severity}</p>
                <p>Medium Severity: {medium_severity}</p>
                <p>Low Severity: {low_severity}</p>
            </div>
            
            <div class="findings">
                <h2>Detailed Findings</h2>
                {findings_html}
            </div>
        </body>
        </html>
        """
        
        summary = self._generate_summary(results['findings'])
        findings_html = self._generate_findings_html(results['findings'])
        
        return html_template.format(
            target=results.get('target', 'Unknown'),
            timestamp=results.get('timestamp', datetime.now().isoformat()),
            total_findings=summary['total'],
            high_severity=summary['high'],
            medium_severity=summary['medium'],
            low_severity=summary['low'],
            findings_html=findings_html
        )
    
    def _generate_summary(self, findings):
        """Generate a summary of findings"""
        summary = {
            'total': len(findings),
            'high': len([f for f in findings if f.get('severity', '').lower() == 'high']),
            'medium': len([f for f in findings if f.get('severity', '').lower() == 'medium']),
            'low': len([f for f in findings if f.get('severity', '').lower() == 'low']),
            'info': len([f for f in findings if f.get('severity', '').lower() == 'info'])
        }
        
        # Calculate categories
        categories = {}
        for finding in findings:
            category = self._categorize_finding(finding)
            categories[category] = categories.get(category, 0) + 1
        
        summary['categories'] = categories
        return summary
    
    def _categorize_finding(self, finding):
        """Categorize a finding based on its title and description"""
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        
        if 'header' in title or 'header' in description:
            return 'Header Analysis'
        elif 'directory' in title or 'path' in title:
            return 'Directory Enumeration'
        elif 'xss' in title or 'xss' in description:
            return 'XSS Vulnerabilities'
        elif 'sql' in title or 'injection' in title:
            return 'SQL Injection'
        elif 'security' in title:
            return 'Security Configuration'
        else:
            return 'Other'
    
    def _generate_findings_html(self, findings):
        """Generate HTML for individual findings"""
        html_parts = []
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            css_class = severity if severity in ['high', 'medium', 'low'] else 'info'
            
            finding_html = f"""
            <div class="finding {css_class}">
                <div class="title">{finding.get('title', 'Unknown Issue')}</div>
                <div class="severity">Severity: {finding.get('severity', 'Unknown')}</div>
                <div class="description">{finding.get('description', 'No description available')}</div>
                <div class="details">{finding.get('details', 'No additional details')}</div>
            </div>
            """
            html_parts.append(finding_html)
        
        return ''.join(html_parts)
    
    def generate_pdf_report(self, results, company_info=None):
        """Generate a comprehensive PDF report of all findings"""
        buffer = io.BytesIO()
        
        # Create the PDF document
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Container for the 'Flowable' objects
        story = []
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.darkblue,
            alignment=TA_LEFT,
            spaceAfter=12
        )
        
        # Title page
        story.append(Paragraph("WebRecon Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Target information
        target_domain = urlparse(results.get('target', 'Unknown')).netloc
        story.append(Paragraph(f"Target: {results.get('target', 'Unknown')}", styles['Heading2']))
        story.append(Paragraph(f"Domain: {target_domain}", styles['Normal']))
        story.append(Paragraph(f"Scan Date: {results.get('timestamp', datetime.now().isoformat())}", styles['Normal']))
        story.append(Paragraph(f"Generated by: WebRecon Security Scanner v1.0", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Company information (if provided)
        if company_info:
            story.append(Paragraph("Company Information", subtitle_style))
            for key, value in company_info.items():
                if value:
                    story.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))
            story.append(Spacer(1, 20))
        
        # Executive summary
        summary = self._generate_summary(results['findings'])
        story.append(Paragraph("Executive Summary", subtitle_style))
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Findings', str(summary['total'])],
            ['High Severity', str(summary['high'])],
            ['Medium Severity', str(summary['medium'])],
            ['Low Severity', str(summary['low'])],
            ['Information', str(summary['info'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 30))
        
        # Risk assessment
        story.append(Paragraph("Risk Assessment", subtitle_style))
        risk_level = self._calculate_risk_level(summary)
        story.append(Paragraph(f"<b>Overall Risk Level:</b> {risk_level}", styles['Normal']))
        story.append(Paragraph(self._get_risk_description(risk_level), styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Key recommendations
        story.append(Paragraph("Key Recommendations", subtitle_style))
        recommendations = self._generate_recommendations(results['findings'])
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        story.append(PageBreak())
        
        # Detailed findings
        story.append(Paragraph("Detailed Security Findings", subtitle_style))
        
        # Group findings by category
        categorized_findings = {}
        for finding in results['findings']:
            category = self._categorize_finding(finding)
            if category not in categorized_findings:
                categorized_findings[category] = []
            categorized_findings[category].append(finding)
        
        # Process each category
        for category, findings in categorized_findings.items():
            story.append(Paragraph(f"{category} ({len(findings)} findings)", styles['Heading3']))
            
            for i, finding in enumerate(findings, 1):
                # Finding header
                severity = finding.get('severity', 'Unknown').upper()
                severity_color = self._get_severity_color(severity)
                
                story.append(Paragraph(f"<b>Finding {i}: {finding.get('title', 'Unknown Issue')}</b>", styles['Normal']))
                story.append(Paragraph(f"<b>Severity:</b> <font color='{severity_color}'>{severity}</font>", styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {finding.get('description', 'No description available')}", styles['Normal']))
                
                if finding.get('details'):
                    story.append(Paragraph(f"<b>Technical Details:</b> {finding.get('details', '')}", styles['Normal']))
                
                # Add remediation if available
                story.append(Paragraph(f"<b>Recommended Action:</b> {self._get_remediation_advice(finding)}", styles['Normal']))
                story.append(Spacer(1, 12))
            
            story.append(Spacer(1, 20))
        
        # Appendix
        story.append(PageBreak())
        story.append(Paragraph("Appendix", subtitle_style))
        story.append(Paragraph("Methodology", styles['Heading3']))
        story.append(Paragraph(self._get_methodology_description(), styles['Normal']))
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Disclaimer", styles['Heading3']))
        story.append(Paragraph(self._get_disclaimer_text(), styles['Normal']))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _calculate_risk_level(self, summary):
        """Calculate overall risk level based on findings"""
        if summary['high'] > 0:
            return "HIGH"
        elif summary['medium'] > 2:
            return "HIGH"
        elif summary['medium'] > 0:
            return "MEDIUM"
        elif summary['low'] > 5:
            return "MEDIUM"
        elif summary['low'] > 0:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_risk_description(self, risk_level):
        """Get description for risk level"""
        descriptions = {
            "HIGH": "Immediate attention required. High-severity vulnerabilities pose significant security risks and should be addressed urgently.",
            "MEDIUM": "Moderate security concerns identified. These issues should be addressed in a timely manner to maintain security posture.",
            "LOW": "Minor security issues identified. These should be addressed as part of regular security maintenance.",
            "MINIMAL": "No significant security issues identified. Continue monitoring and maintaining current security practices."
        }
        return descriptions.get(risk_level, "Risk level assessment unavailable.")
    
    def _generate_recommendations(self, findings):
        """Generate key recommendations based on findings"""
        recommendations = []
        categories = {}
        
        for finding in findings:
            category = self._categorize_finding(finding)
            severity = finding.get('severity', '').lower()
            if category not in categories:
                categories[category] = {'high': 0, 'medium': 0, 'low': 0}
            if severity in categories[category]:
                categories[category][severity] += 1
        
        # Generate recommendations based on categories
        if categories.get('Security Configuration', {}).get('high', 0) > 0:
            recommendations.append("Implement missing security headers (HSTS, CSP, X-Frame-Options) to protect against common web attacks.")
        
        if categories.get('XSS Vulnerabilities', {}).get('high', 0) > 0:
            recommendations.append("Address XSS vulnerabilities by implementing proper input validation and output encoding.")
        
        if categories.get('SQL Injection', {}).get('high', 0) > 0:
            recommendations.append("Fix SQL injection vulnerabilities by using parameterized queries and input validation.")
        
        if categories.get('Directory Enumeration', {}).get('medium', 0) > 0:
            recommendations.append("Secure exposed directories and files by implementing proper access controls.")
        
        if categories.get('Header Analysis', {}).get('low', 0) > 0:
            recommendations.append("Review server configuration to minimize information disclosure in HTTP headers.")
        
        if not recommendations:
            recommendations.append("Continue maintaining current security practices and conduct regular security assessments.")
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors_map = {
            'HIGH': 'red',
            'MEDIUM': 'orange',
            'LOW': 'blue',
            'INFO': 'green'
        }
        return colors_map.get(severity, 'black')
    
    def _get_remediation_advice(self, finding):
        """Get remediation advice for a finding"""
        title = finding.get('title', '').lower()
        
        if 'missing security header' in title:
            return "Configure the web server or application to include the missing security header with appropriate values."
        elif 'xss' in title:
            return "Implement proper input validation, output encoding, and use Content Security Policy (CSP) headers."
        elif 'sql injection' in title:
            return "Use parameterized queries, input validation, and implement least privilege database access."
        elif 'directory listing' in title:
            return "Disable directory browsing in web server configuration and implement proper access controls."
        elif 'information disclosure' in title:
            return "Configure server to minimize information leakage in headers and error messages."
        else:
            return "Review the security configuration and implement appropriate security controls for this finding."
    
    def _get_methodology_description(self):
        """Get methodology description"""
        return """This security assessment was conducted using WebRecon, an automated web penetration testing toolkit. The assessment included the following tests:

• HTTP Header Analysis: Examination of response headers for security configurations and information disclosure
• Security Header Assessment: Verification of security headers like HSTS, CSP, X-Frame-Options, etc.
• Directory Enumeration: Discovery of accessible directories and files using common wordlists
• Cross-Site Scripting (XSS) Testing: Detection of XSS vulnerabilities in forms and URL parameters
• SQL Injection Testing: Identification of SQL injection vulnerabilities using various payloads

The assessment was performed in a controlled manner with rate limiting to minimize impact on the target system."""
    
    def _get_disclaimer_text(self):
        """Get disclaimer text"""
        return """IMPORTANT DISCLAIMER:

This security assessment report is intended for authorized testing purposes only. The findings and recommendations contained in this report should be used solely for improving the security posture of the assessed system.

The assessment was conducted using automated tools and may not identify all potential security vulnerabilities. Manual testing and code review are recommended for comprehensive security evaluation.

This report is confidential and should be treated as sensitive information. Distribution should be limited to authorized personnel only.

The WebRecon team assumes no responsibility for any damages or issues that may arise from the use of this report or the implementation of its recommendations."""
