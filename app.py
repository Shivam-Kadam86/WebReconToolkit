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
    page_title="WebRecon - Cyber Penetration Toolkit",
    page_icon="💀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Hacker Theme CSS
st.markdown("""
<style>
    /* Global Dark Theme */
    .stApp {
        background-color: #0a0a0a;
        color: #00ff41;
    }
    
    /* Main content area */
    .main .block-container {
        background-color: #111111;
        padding: 2rem;
        border-radius: 15px;
        border: 1px solid #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(90deg, #000000, #1a1a1a, #000000);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        border: 2px solid #00ff41;
        box-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
        position: relative;
        overflow: hidden;
        text-align: center;
    }
    
    .main-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.1), transparent);
        animation: scan 3s infinite;
    }
    
    @keyframes scan {
        0% { left: -100%; }
        100% { left: 100%; }
    }
    
    .main-header h1 {
        color: #00ff41;
        text-align: center;
        margin: 0;
        font-weight: bold;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 10px #00ff41;
        font-size: 3rem;
        letter-spacing: 3px;
    }
    
    .main-header p {
        color: #00ff41;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 5px #00ff41;
        margin-top: 1rem;
        font-size: 1.2rem;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #000000;
        border-right: 2px solid #00ff41;
    }
    
    /* Warning box - hacker style */
    .warning-box {
        background: linear-gradient(135deg, #1a0000, #2a0000);
        border: 2px solid #ff0040;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 0 25px rgba(255, 0, 64, 0.3);
        color: #ff0040;
        font-family: 'Courier New', monospace;
        position: relative;
        overflow: hidden;
    }
    
    .warning-box::before {
        content: '[WARNING]';
        position: absolute;
        top: 10px;
        right: 10px;
        background: #ff0040;
        color: #000000;
        padding: 5px 10px;
        border-radius: 5px;
        font-size: 0.8rem;
        font-weight: bold;
    }
    
    .warning-box h3 {
        color: #ff0040;
        text-shadow: 0 0 10px #ff0040;
        font-family: 'Courier New', monospace;
    }
    
    /* Vulnerability cards - cyberpunk style */
    .vulnerability-high {
        background: linear-gradient(135deg, #2a0000, #1a0000);
        border-left: 5px solid #ff0040;
        border-right: 1px solid #ff0040;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(255, 0, 64, 0.4);
        color: #ff0040;
        font-family: 'Courier New', monospace;
        position: relative;
    }
    
    .vulnerability-high::before {
        content: '[CRITICAL]';
        position: absolute;
        top: 5px;
        right: 10px;
        background: #ff0040;
        color: #000000;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 0.7rem;
        font-weight: bold;
    }
    
    .vulnerability-medium {
        background: linear-gradient(135deg, #2a1a00, #1a1000);
        border-left: 5px solid #ff8800;
        border-right: 1px solid #ff8800;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(255, 136, 0, 0.3);
        color: #ff8800;
        font-family: 'Courier New', monospace;
        position: relative;
    }
    
    .vulnerability-medium::before {
        content: '[HIGH]';
        position: absolute;
        top: 5px;
        right: 10px;
        background: #ff8800;
        color: #000000;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 0.7rem;
        font-weight: bold;
    }
    
    .vulnerability-low {
        background: linear-gradient(135deg, #002a2a, #001a1a);
        border-left: 5px solid #00ffff;
        border-right: 1px solid #00ffff;
        padding: 1.2rem;
        margin: 0.8rem 0;
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
        color: #00ffff;
        font-family: 'Courier New', monospace;
        position: relative;
    }
    
    .vulnerability-low::before {
        content: '[INFO]';
        position: absolute;
        top: 5px;
        right: 10px;
        background: #00ffff;
        color: #000000;
        padding: 2px 8px;
        border-radius: 3px;
        font-size: 0.7rem;
        font-weight: bold;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(45deg, #000000, #1a1a1a);
        color: #00ff41;
        border: 2px solid #00ff41;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: bold;
        font-family: 'Courier New', monospace;
        transition: all 0.3s ease;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stButton > button:hover {
        background: #00ff41;
        color: #000000;
        transform: translateY(-2px);
        box-shadow: 0 0 25px rgba(0, 255, 65, 0.8);
    }
    
    /* Input fields */
    .stTextInput > div > div > input {
        background-color: #1a1a1a;
        color: #00ff41;
        border: 1px solid #00ff41;
        border-radius: 10px;
        font-family: 'Courier New', monospace;
    }
    
    .stSelectbox > div > div > select {
        background-color: #1a1a1a;
        color: #00ff41;
        border: 1px solid #00ff41;
        border-radius: 10px;
        font-family: 'Courier New', monospace;
    }
    
    /* Checkbox styling */
    .stCheckbox > label {
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    /* Metrics styling */
    [data-testid="metric-container"] {
        background: linear-gradient(45deg, #000000, #1a1a1a);
        border: 1px solid #00ff41;
        padding: 1rem;
        border-radius: 15px;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
    }
    
    [data-testid="metric-container"] > div {
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    /* Text styling */
    .stMarkdown {
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #00ff41;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 5px #00ff41;
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: #1a1a1a;
        color: #00ff41;
        border: 1px solid #00ff41;
        border-radius: 10px;
        font-family: 'Courier New', monospace;
    }
    
    /* Progress bar */
    .stProgress > div > div > div {
        background-color: #00ff41;
    }
    
    /* Success/Error messages */
    .stSuccess {
        background-color: #001100;
        color: #00ff41;
        border: 1px solid #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    .stError {
        background-color: #110000;
        color: #ff0040;
        border: 1px solid #ff0040;
        font-family: 'Courier New', monospace;
    }
    
    .stWarning {
        background-color: #111100;
        color: #ffff00;
        border: 1px solid #ffff00;
        font-family: 'Courier New', monospace;
    }
    
    /* Terminal-like font for code blocks */
    code {
        background-color: #000000;
        color: #00ff41;
        font-family: 'Courier New', monospace;
        border: 1px solid #00ff41;
        border-radius: 5px;
        padding: 2px 4px;
    }
    
    /* Download button special styling */
    .stDownloadButton > button {
        background: linear-gradient(45deg, #1a1a1a, #2a2a2a);
        color: #00ff41;
        border: 2px solid #00ff41;
        border-radius: 15px;
        font-family: 'Courier New', monospace;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stDownloadButton > button:hover {
        background: #00ff41;
        color: #000000;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.8);
    }
    
    /* Sidebar title */
    .css-1d391kg h1 {
        color: #00ff41;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 10px #00ff41;
    }
    
    /* General text in sidebar */
    .css-1d391kg .stMarkdown {
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>💀 WebRecon - Cyber Penetration Toolkit 💀</h1>
        <p>[ ELITE HACKER SECURITY ASSESSMENT SYSTEM ]</p>
        <p style="font-size: 0.9rem; margin-top: 0.5rem;">>>> AUTHORIZED TESTING PROTOCOL ACTIVE <<<</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Warning and Disclaimer
    st.markdown("""
    <div class="warning-box">
        <h3>⚠️ [LEGAL PROTOCOL INITIATED]</h3>
        <p><strong>>>> AUTHORIZED PENETRATION TESTING ONLY <<<</strong></p>
        <p>BY EXECUTING THIS SYSTEM, YOU CONFIRM:</p>
        <ul>
            <li>TARGET SYSTEM ACCESS EXPLICITLY AUTHORIZED</li>
            <li>MALICIOUS INTENT: DENIED</li>
            <li>UNAUTHORIZED PENTESTING: ILLEGAL ACTIVITY</li>
            <li>LEGAL COMPLIANCE: USER RESPONSIBILITY</li>
        </ul>
        <p><em>[ RESTRICTION: AUTHORIZED TARGETS ONLY ]</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.title("⚡ CYBER SCAN CONFIG")
    
    # URL input
    target_url = st.sidebar.text_input(
        ">> TARGET SYSTEM URL",
        placeholder="https://target-system.com",
        help="Enter target system URL for penetration testing"
    )
    
    # Scan options
    st.sidebar.subheader("🔥 ATTACK MODULES")
    
    scan_headers = st.sidebar.checkbox("🔍 HEADER RECONNAISSANCE", value=True)
    scan_security_headers = st.sidebar.checkbox("🛡️ SECURITY ANALYSIS", value=True)
    scan_directories = st.sidebar.checkbox("📁 DIRECTORY BRUTEFORCE", value=True)
    scan_xss = st.sidebar.checkbox("⚡ XSS EXPLOITATION", value=True)
    scan_sql = st.sidebar.checkbox("💉 SQL INJECTION TEST", value=True)
    
    # Advanced options
    with st.sidebar.expander("⚙️ SYSTEM CONFIG"):
        timeout = st.slider("TIMEOUT (seconds)", 1, 30, 10)
        threads = st.slider("THREAD COUNT", 1, 10, 5)
        ai_explanations = st.checkbox("🤖 AI CYBER ANALYSIS", value=True)
    
    # API Key Management
    with st.sidebar.expander("🔑 API KEY MANAGEMENT"):
        st.markdown("**OpenAI API Key Configuration**")
        new_api_key = st.text_input(
            "Enter new OpenAI API Key",
            type="password",
            placeholder="sk-...",
            help="Update your OpenAI API key for AI explanations"
        )
        if st.button("🔄 UPDATE API KEY"):
            if new_api_key and new_api_key.startswith("sk-"):
                import os
                os.environ["OPENAI_API_KEY"] = new_api_key
                st.success("API key updated successfully!")
                st.rerun()
            else:
                st.error("Invalid API key format. Must start with 'sk-'")
    
    # Authorization confirmation
    st.sidebar.subheader("🔐 ACCESS AUTHORIZATION")
    authorized = st.sidebar.checkbox(
        "CONFIRM: AUTHORIZED TARGET ACCESS",
        help="Explicit permission required for target system penetration"
    )
    
    # Always display welcome information first
    display_welcome_info()
    
    # Main content area
    if target_url and authorized:
        if validate_url(target_url):
            if st.sidebar.button("💀 INITIATE HACK", type="primary"):
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
    st.markdown("## 💀 WEBRECON CYBER OPERATION CENTER")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### ⚡ RECONNAISSANCE MODULES
        - **HEADER ANALYSIS**: HTTP response header exploitation
        - **SECURITY BYPASS**: HSTS, CSP, X-Frame bypass techniques
        - **DIRECTORY HACK**: Stealth enumeration protocols
        """)
    
    with col2:
        st.markdown("""
        ### 💥 EXPLOITATION FRAMEWORKS
        - **XSS INJECTION**: Cross-site scripting attack vectors
        - **SQL PENETRATION**: Database injection exploits
        - **AI THREAT INTEL**: Advanced vulnerability analysis
        """)
    
    st.markdown("---")
    st.markdown("## 📊 THREAT ASSESSMENT MATRIX")
    st.markdown("*CRITICAL VULNERABILITY INTELLIGENCE:*")
    
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
            status_text.text(f"🔍 EXECUTING HEADER RECONNAISSANCE... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            header_results = scanner.analyze_headers()
            results['findings'].extend(header_results)
            
            display_results("Header Analysis", header_results, ai_explainer)
        
        # Security Headers
        if scan_security_headers:
            current_scan += 1
            status_text.text(f"🛡️ ANALYZING SECURITY BYPASSES... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            security_results = scanner.check_security_headers()
            results['findings'].extend(security_results)
            
            display_results("SECURITY ANALYSIS", security_results, ai_explainer)
        
        # Directory Enumeration
        if scan_directories:
            current_scan += 1
            status_text.text(f"📁 INITIATING DIRECTORY BRUTEFORCE... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            directory_results = scanner.enumerate_directories()
            results['findings'].extend(directory_results)
            
            display_results("DIRECTORY HACK", directory_results, ai_explainer)
        
        # XSS Detection
        if scan_xss:
            current_scan += 1
            status_text.text(f"⚡ DEPLOYING XSS PAYLOADS... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            xss_results = scanner.test_xss()
            results['findings'].extend(xss_results)
            
            display_results("XSS EXPLOITATION", xss_results, ai_explainer)
        
        # SQL Injection
        if scan_sql:
            current_scan += 1
            status_text.text(f"💉 EXECUTING SQL INJECTION ATTACKS... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            sql_results = scanner.test_sql_injection()
            results['findings'].extend(sql_results)
            
            display_results("SQL PENETRATION", sql_results, ai_explainer)
        
        # Completion
        progress_bar.progress(1.0)
        status_text.text("💀 PENETRATION TESTING COMPLETE!")
        
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
        try:
            pdf_report = report_generator.generate_pdf_report(results)
            st.download_button(
                label="📑 Download PDF Report",
                data=pdf_report,
                file_name=f"security_assessment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                key="pdf_download"
            )
        except Exception as e:
            st.error(f"PDF generation failed: {str(e)}")
            st.info("Please ensure all scan data is available before generating PDF")

if __name__ == "__main__":
    main()
