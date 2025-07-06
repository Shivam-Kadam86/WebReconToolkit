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

# Custom CSS for Cyber Sci-Fi styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600&display=swap');
    
    /* Global Theme */
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a0826 25%, #2d1b69 50%, #0c0c0c 100%);
        color: #00ffff;
    }
    
    /* Main Header */
    .main-header {
        text-align: center;
        padding: 2.5rem 0;
        background: linear-gradient(45deg, #00ffff, #ff00ff, #ffff00, #00ffff);
        background-size: 400% 400%;
        animation: cyberpulse 3s ease-in-out infinite;
        color: #000;
        border-radius: 15px;
        margin-bottom: 2rem;
        border: 2px solid #00ffff;
        box-shadow: 0 0 30px rgba(0,255,255,0.5), inset 0 0 30px rgba(255,0,255,0.2);
        font-family: 'Orbitron', monospace;
        text-transform: uppercase;
        letter-spacing: 3px;
    }
    
    @keyframes cyberpulse {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    /* Warning Box */
    .warning-box {
        background: linear-gradient(135deg, #1a0826, #2d1b69);
        border: 2px solid #ff6b35;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 0 20px rgba(255,107,53,0.4), inset 0 0 20px rgba(255,107,53,0.1);
        color: #00ffff;
        font-family: 'Rajdhani', sans-serif;
        position: relative;
        overflow: hidden;
    }
    
    .warning-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,107,53,0.2), transparent);
        animation: scan 2s infinite;
    }
    
    @keyframes scan {
        0% { left: -100%; }
        100% { left: 100%; }
    }
    
    /* Vulnerability Cards */
    .vulnerability-high {
        background: linear-gradient(135deg, #2d0a0a, #4d1414);
        border-left: 5px solid #ff0040;
        border-radius: 12px;
        padding: 1.2rem;
        margin: 0.8rem 0;
        box-shadow: 0 0 15px rgba(255,0,64,0.4), inset 0 0 15px rgba(255,0,64,0.1);
        color: #ff6b9d;
        font-family: 'Rajdhani', sans-serif;
        border: 1px solid #ff0040;
        position: relative;
    }
    
    .vulnerability-medium {
        background: linear-gradient(135deg, #2d2d0a, #4d4d14);
        border-left: 5px solid #ffaa00;
        border-radius: 12px;
        padding: 1.2rem;
        margin: 0.8rem 0;
        box-shadow: 0 0 15px rgba(255,170,0,0.4), inset 0 0 15px rgba(255,170,0,0.1);
        color: #ffdd6b;
        font-family: 'Rajdhani', sans-serif;
        border: 1px solid #ffaa00;
        position: relative;
    }
    
    .vulnerability-low {
        background: linear-gradient(135deg, #0a2d2d, #144d4d);
        border-left: 5px solid #00aaff;
        border-radius: 12px;
        padding: 1.2rem;
        margin: 0.8rem 0;
        box-shadow: 0 0 15px rgba(0,170,255,0.4), inset 0 0 15px rgba(0,170,255,0.1);
        color: #6bddff;
        font-family: 'Rajdhani', sans-serif;
        border: 1px solid #00aaff;
        position: relative;
    }
    
    /* Cyber Grid Lines */
    .vulnerability-high::after,
    .vulnerability-medium::after,
    .vulnerability-low::after {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 2px;
        height: 100%;
        background: linear-gradient(to bottom, transparent 0%, currentColor 50%, transparent 100%);
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 0.3; }
        50% { opacity: 1; }
    }
    
    /* Sidebar Styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #0a0a0a, #1a0826);
        border-right: 2px solid #00ffff;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(45deg, #00ffff, #ff00ff);
        color: #000;
        border: none;
        border-radius: 8px;
        font-family: 'Orbitron', monospace;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        box-shadow: 0 0 15px rgba(0,255,255,0.3);
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        box-shadow: 0 0 25px rgba(0,255,255,0.6);
        transform: translateY(-2px);
    }
    
    /* Text Inputs */
    .stTextInput > div > div > input {
        background: rgba(0,0,0,0.8);
        border: 1px solid #00ffff;
        border-radius: 8px;
        color: #00ffff;
        font-family: 'Rajdhani', sans-serif;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #ff00ff;
        box-shadow: 0 0 10px rgba(255,0,255,0.3);
    }
    
    /* Metrics */
    .metric-container {
        background: linear-gradient(135deg, #1a0826, #2d1b69);
        border: 1px solid #00ffff;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 0 15px rgba(0,255,255,0.2);
    }
    
    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Orbitron', monospace;
        color: #00ffff;
        text-shadow: 0 0 10px rgba(0,255,255,0.5);
    }
    
    p, div, span {
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Progress Bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #00ffff, #ff00ff, #ffff00);
    }
    
    /* Selectbox */
    .stSelectbox > div > div > select {
        background: rgba(0,0,0,0.8);
        border: 1px solid #00ffff;
        color: #00ffff;
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Checkbox */
    .stCheckbox > label {
        color: #00ffff;
        font-family: 'Rajdhani', sans-serif;
    }
    
    /* Terminal Effect */
    .terminal-text {
        font-family: 'Courier New', monospace;
        background: #000;
        color: #00ff00;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #00ff00;
        margin: 10px 0;
    }
    
    /* Glitch Effect for Headers */
    .glitch {
        position: relative;
        animation: glitch 2s infinite;
    }
    
    @keyframes glitch {
        0%, 100% { transform: translate(0); }
        20% { transform: translate(-2px, 2px); }
        40% { transform: translate(-2px, -2px); }
        60% { transform: translate(2px, 2px); }
        80% { transform: translate(2px, -2px); }
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header glitch">
        <h1>⚡ CYBERRECON - NEURAL INTRUSION MATRIX ⚡</h1>
        <p>>>> CYBERSECURITY INFILTRATION PROTOCOL - AUTHORIZED ACCESS ONLY <<<</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Warning and Disclaimer
    st.markdown("""
    <div class="warning-box">
        <h3>🚨 NEURAL SECURITY PROTOCOL - ACCESS RESTRICTIONS 🚨</h3>
        <p><strong>>>> AUTHORIZED CYBERSECURITY OPERATIONS ONLY <<<</strong></p>
        <p>NEURAL LINK ESTABLISHED. CONFIRM AUTHORIZATION PARAMETERS:</p>
        <ul>
            <li>⚡ EXPLICIT TARGET AUTHORIZATION VERIFIED</li>
            <li>⚡ NO MALICIOUS INTENT ALGORITHMS DETECTED</li>
            <li>⚡ CYBER-LAW COMPLIANCE PROTOCOLS ACTIVE</li>
            <li>⚡ FULL LEGAL RESPONSIBILITY MATRIX ACCEPTED</li>
        </ul>
        <p><em>>>> WARNING: UNAUTHORIZED NEURAL INTRUSION DETECTED BY CYBER-ENFORCEMENT <<<</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.title("⚡ NEURAL INTERFACE CONTROL")
    
    # URL input
    target_url = st.sidebar.text_input(
        ">>> TARGET NETWORK ADDRESS <<<",
        placeholder="https://target-system.net",
        help="Input authorized network endpoint for cyber-infiltration"
    )
    
    # Scan options
    st.sidebar.subheader("🔬 INTRUSION PROTOCOLS")
    
    scan_headers = st.sidebar.checkbox("⚡ Neural Header Analysis", value=True)
    scan_security_headers = st.sidebar.checkbox("🛡️ Security Matrix Scan", value=True)
    scan_directories = st.sidebar.checkbox("📁 Directory Ghost Protocol", value=True)
    scan_xss = st.sidebar.checkbox("💉 XSS Injection Vector", value=True)
    scan_sql = st.sidebar.checkbox("🗃️ Database Breach Protocol", value=True)
    
    # Advanced options
    with st.sidebar.expander("🔧 ADVANCED CYBER-CONFIGS"):
        timeout = st.slider("Neural Timeout (seconds)", 1, 30, 10)
        threads = st.slider("Parallel Processing Units", 1, 10, 5)
        ai_explanations = st.checkbox("🧠 AI Neural Explanations", value=True)
    
    # Authorization confirmation
    st.sidebar.subheader("🔐 AUTHORIZATION MATRIX")
    authorized = st.sidebar.checkbox(
        "✅ CYBER-CLEARANCE VERIFIED",
        help="Confirm authorized access to target network infrastructure"
    )
    
    # Always display welcome information first
    display_welcome_info()
    
    # Main content area
    if target_url and authorized:
        if validate_url(target_url):
            if st.sidebar.button("⚡ INITIATE NEURAL BREACH ⚡", type="primary"):
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
    st.markdown("## ⚡ CYBER-INFILTRATION CAPABILITIES")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🧠 NEURAL ANALYSIS MATRIX
        - **⚡ Header Intrusion**: Neural analysis of HTTP transmission protocols
        - **🛡️ Security Breach Detection**: Matrix scan for HSTS, CSP, X-Frame vulnerabilities
        - **📁 Ghost Directory Protocol**: Phantom enumeration of hidden data structures
        """)
    
    with col2:
        st.markdown("""
        ### 🔥 VULNERABILITY EXPLOITATION VECTORS
        - **💉 XSS Neural Injection**: Cross-site scripting breach protocols
        - **🗃️ Database Infiltration**: SQL injection attack vectors
        - **🧠 AI Threat Analysis**: Neural network vulnerability explanations
        """)
    
    st.markdown("---")
    st.markdown("## 🚨 CYBER-THREAT ASSESSMENT MATRIX")
    st.markdown("*>>> Neural scan results visualization protocols:*")
    
    # Example vulnerability display
    st.markdown("""
    <div class="vulnerability-high">
        <strong>⚠️ CRITICAL BREACH DETECTED</strong> - Security Matrix Compromised<br>
        <small>>>> Neural scan detected missing cyber-defense protocols in target system <<<</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="vulnerability-medium">
        <strong>🔶 MODERATE SECURITY FLAW</strong> - Directory Ghost Exposure<br>
        <small>>>> Target system allows unauthorized phantom browsing of sensitive data structures <<<</small>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="vulnerability-low">
        <strong>🔹 MINOR DATA LEAK</strong> - Server Neural Signature Exposed<br>
        <small>>>> System broadcasting internal architecture information to potential cyber-threats <<<</small>
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
            status_text.text(f"⚡ Initiating neural header intrusion... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            header_results = scanner.analyze_headers()
            results['findings'].extend(header_results)
            
            display_results("⚡ Neural Header Analysis", header_results, ai_explainer)
        
        # Security Headers
        if scan_security_headers:
            current_scan += 1
            status_text.text(f"🛡️ Breaching security matrix protocols... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            security_results = scanner.check_security_headers()
            results['findings'].extend(security_results)
            
            display_results("🛡️ Security Matrix Breach", security_results, ai_explainer)
        
        # Directory Enumeration
        if scan_directories:
            current_scan += 1
            status_text.text(f"👻 Executing ghost directory protocol... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            directory_results = scanner.enumerate_directories()
            results['findings'].extend(directory_results)
            
            display_results("👻 Ghost Directory Infiltration", directory_results, ai_explainer)
        
        # XSS Detection
        if scan_xss:
            current_scan += 1
            status_text.text(f"💉 Deploying XSS injection vectors... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            xss_results = scanner.test_xss()
            results['findings'].extend(xss_results)
            
            display_results("💉 XSS Neural Injection", xss_results, ai_explainer)
        
        # SQL Injection
        if scan_sql:
            current_scan += 1
            status_text.text(f"🗃️ Infiltrating database neural networks... ({current_scan}/{total_scans})")
            progress_bar.progress(current_scan / total_scans)
            
            sql_results = scanner.test_sql_injection()
            results['findings'].extend(sql_results)
            
            display_results("🗃️ Database Breach Protocol", sql_results, ai_explainer)
        
        # Completion
        progress_bar.progress(1.0)
        status_text.text("🔥 NEURAL BREACH SEQUENCE COMPLETE - CYBER-INFILTRATION SUCCESSFUL! 🔥")
        
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
