import json
import csv
import io
from datetime import datetime

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
