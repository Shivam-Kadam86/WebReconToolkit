import streamlit as st
import requests
import urllib.parse
import socket
import time
import json
from datetime import datetime
from modules.scanner import WebScanner
from modules.ai_explainer import AIExplainer
from modules.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="WebRecon - Web Penetration Testing Toolkit",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 2px solid #f39c12;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #000000;
    }
    .vulnerability-high {
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #000000;
    }
    .vulnerability-medium {
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #000000;
    }
    .vulnerability-low {
        background-color: #d1ecf1;
        border-left: 5px solid #17a2b8;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #000000;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔒 WebRecon - Web Penetration Testing Toolkit</h1>
        <p>Professional Security Assessment Tool for Authorized Testing</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Warning and Disclaimer
    st.markdown("""
    <div class="warning-box">
        <h3>⚠️ IMPORTANT LEGAL DISCLAIMER</h3>
        <p><strong>This tool is intended for authorized security testing only.</strong></p>
        <p>By using this application, you agree that:</p>
        <ul>
            <li>You have explicit permission to test the target website</li>
            <li>You will not use this tool for malicious purposes</li>
            <li>You understand that unauthorized penetration testing is illegal</li>
            <li>You are responsible for complying with all applicable laws and regulations</li>
        </ul>
        <p><em>Only test websites you own or have explicit written permission to test.</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.title("🛠️ Scan Configuration")
    
    # URL input
    target_url = st.sidebar.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Enter the URL you are authorized to test"
    )
    
    # Scan options
    st.sidebar.subheader("Scan Options")
    
    scan_headers = st.sidebar.checkbox("Header Analysis", value=True)
    scan_security_headers = st.sidebar.checkbox("Security Headers", value=True)
    scan_directories = st.sidebar.checkbox("Directory Enumeration", value=True)
    scan_xss = st.sidebar.checkbox("XSS Detection", value=True)
    scan_sql = st.sidebar.checkbox("SQL Injection", value=True)
    
    # Advanced options
    with st.sidebar.expander("Advanced Options"):
        timeout = st.slider("Request Timeout (seconds)", 1, 30, 10)
        threads = st.slider("Concurrent Threads", 1, 10, 5)
        ai_explanations = st.checkbox("AI-Powered Explanations", value=True)
    
    # Authorization confirmation
    st.sidebar.subheader("Authorization Confirmation")
    authorized = st.sidebar.checkbox(
        "I confirm I have authorization to test this target",
        help="You must have explicit permission to test the target URL"
    )
    
    # Always display welcome information first
    display_welcome_info()
    
    # Main content area
    if target_url and authorized:
        if validate_url(target_url):
            if st.sidebar.button("🚀 Start Scan", type="primary"):
                run_scan(
                    target_url,
                    scan_headers,
                    scan_security_headers,
                    scan_directories,
                    scan_xss,
                    scan_sql,
                    timeout,
                    threads,
                    ai_explanations
                )
        else:
            st.error("Please enter a valid URL (must include http:// or https://)")
    
    elif target_url and not authorized:
        st.error("You must confirm authorization before starting a scan")

def validate_url(url):
    """Validate the input URL format"""
    try:
        parsed = urllib.parse.urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    except:
        return False

def display_welcome_info():
    """Display welcome information and tool capabilities"""
    st.markdown("## 🎯 WebRecon Capabilities")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔍 Security Analysis
        - **Header Inspection**: Analyze HTTP response headers
        - **Security Headers**: Check for HSTS, CSP, X-Frame-Options, etc.
        - **Directory Enumeration**: Discover hidden directories and files
        """)
    
    with col2:
        st.markdown("""
        ### 🛡️ Vulnerability Detection
        - **XSS Testing**: Cross-site scripting vulnerability detection
        - **SQL Injection**: Database injection point identification
        - **AI Explanations**: Detailed vulnerability explanations
        """)
    
    st.markdown("---")
    st.markdown("## 📊 Example Security Report")
    st.markdown("*This is what vulnerability findings look like:*")
    
    # Example vulnerability display
    st.markdown("""
    <div class="vulnerability-high">
        <strong>HIGH SEVERITY</strong> - Missing Security Headers<br>
        <small>The application is missing critical security headers that protect against common attacks.</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="vulnerability-medium">
        <strong>MEDIUM SEVERITY</strong> - Directory Listing Enabled<br>
        <small>Web server allows directory browsing which may expose sensitive files.</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="vulnerability-low">
        <strong>LOW SEVERITY</strong> - Server Information Disclosure<br>
        <small>Server header reveals software version information to potential attackers.</small>
    </div>
    """, unsafe_allow_html=True)

def run_scan(target_url, scan_headers, scan_security_headers, scan_directories, scan_xss, scan_sql, timeout, threads, ai_explanations):
    """Execute the penetration testing scan"""
    
    # Initialize scanner
    scanner = WebScanner(target_url, timeout, threads)
    ai_explainer = AIExplainer() if ai_explanations else None
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Results storage
    results = {
        'target': target_url,
        'timestamp': datetime.now().isoformat(),
        'findings': []
    }
    
    total_scans = sum([scan_headers, scan_security_headers, scan_directories, scan_xss, scan_sql])
    current_scan = 0
    
    try:
        # Header Analysis
        if scan_headers:
            current_scan += 1
            status_text.text(f"🔍 Analyzing HTTP headers... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            header_results = scanner.analyze_headers()
            results['findings'].extend(header_results)
            
            display_results("Header Analysis", header_results, ai_explainer)
        
        # Security Headers
        if scan_security_headers:
            current_scan += 1
            status_text.text(f"🛡️ Checking security headers... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            security_results = scanner.check_security_headers()
            results['findings'].extend(security_results)
            
            display_results("Security Headers", security_results, ai_explainer)
        
        # Directory Enumeration
        if scan_directories:
            current_scan += 1
            status_text.text(f"📁 Enumerating directories... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            directory_results = scanner.enumerate_directories()
            results['findings'].extend(directory_results)
            
            display_results("Directory Enumeration", directory_results, ai_explainer)
        
        # XSS Detection
        if scan_xss:
            current_scan += 1
            status_text.text(f"🔓 Testing for XSS vulnerabilities... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            xss_results = scanner.test_xss()
            results['findings'].extend(xss_results)
            
            display_results("XSS Detection", xss_results, ai_explainer)
        
        # SQL Injection
        if scan_sql:
            current_scan += 1
            status_text.text(f"💉 Testing for SQL injection... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            sql_results = scanner.test_sql_injection()
            results['findings'].extend(sql_results)
            
            display_results("SQL Injection", sql_results, ai_explainer)
        
        # Completion
        progress_bar.progress(1.0)
        status_text.text("✅ Scan completed successfully!")
        
        # Generate report
        generate_final_report(results)
        
    except Exception as e:
        st.error(f"Scan failed: {str(e)}")
        progress_bar.progress(0.0)
        status_text.text("❌ Scan failed")

def display_results(scan_type, results, ai_explainer):
    """Display scan results in the UI"""
    st.subheader(f"📋 {scan_type} Results")
    
    if not results:
        st.success("No issues found in this category.")
        return
    
    for finding in results:
        severity = finding.get('severity', 'info').lower()
        
        if severity == 'high':
            css_class = "vulnerability-high"
        elif severity == 'medium':
            css_class = "vulnerability-medium"
        else:
            css_class = "vulnerability-low"
        
        with st.expander(f"{severity.upper()} - {finding['title']}"):
            st.markdown(f"**Description:** {finding['description']}")
            st.markdown(f"**Severity:** {finding['severity']}")
            
            if 'details' in finding:
                st.markdown(f"**Details:** {finding['details']}")
            
            if ai_explainer:
                with st.spinner("Getting AI explanation..."):
                    explanation = ai_explainer.explain_vulnerability(finding)
                    if explanation:
                        st.markdown("**AI Explanation:**")
                        st.info(explanation)

def generate_final_report(results):
    """Generate and display the final security report"""
    st.markdown("---")
    st.subheader("📊 Final Security Report")
    
    # Summary statistics
    total_findings = len(results['findings'])
    high_severity = len([f for f in results['findings'] if f.get('severity') == 'high'])
    medium_severity = len([f for f in results['findings'] if f.get('severity') == 'medium'])
    low_severity = len([f for f in results['findings'] if f.get('severity') == 'low'])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Findings", total_findings)
    with col2:
        st.metric("High Severity", high_severity)
    with col3:
        st.metric("Medium Severity", medium_severity)
    with col4:
        st.metric("Low Severity", low_severity)
    
    # Export functionality
    st.markdown("---")
    st.subheader("📊 Download Reports")
    report_generator = ReportGenerator()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Download JSON Report"):
            json_report = report_generator.generate_json_report(results)
            st.download_button(
                label="Download JSON",
                data=json_report,
                file_name=f"webrecon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📋 Download CSV Report"):
            csv_report = report_generator.generate_csv_report(results)
            st.download_button(
                label="Download CSV",
                data=csv_report,
                file_name=f"webrecon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col3:
        if st.button("📑 Download PDF Report"):
            pdf_report = report_generator.generate_pdf_report(results)
            st.download_button(
                label="Download Professional PDF Report",
                data=pdf_report,
                file_name=f"security_assessment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )

if __name__ == "__main__":
    main()
