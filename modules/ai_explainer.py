import json
import os

class AIExplainer:
    def __init__(self):
        # Check for different API providers
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.google_key = os.getenv("GOOGLE_API_KEY", "")
        self.custom_key = os.getenv("AI_API_KEY", "")
        
        # Initialize client based on available keys
        self.client = None
        self.provider = None
        
        if self.openai_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.openai_key)
                self.provider = "OpenAI"
            except ImportError:
                pass
        elif self.anthropic_key:
            self.provider = "Anthropic"
            # Anthropic client would be initialized here if library is available
        elif self.google_key:
            self.provider = "Google"
            # Google client would be initialized here if library is available  
        elif self.custom_key:
            self.provider = "Custom"
            # Custom API client logic would go here
    
    def explain_vulnerability(self, vulnerability):
        """Generate AI explanation for a vulnerability"""
        if not self.client and not self.provider:
            return "AI explanations require an API key to be configured. Please set up your API key in the sidebar."
        
        if self.provider == "OpenAI" and not self.client:
            return "OpenAI client initialization failed. Please check your API key."
        
        try:
            prompt = f"""
            Explain the following security vulnerability in a clear, educational manner:
            
            Title: {vulnerability.get('title', 'Unknown Vulnerability')}
            Description: {vulnerability.get('description', 'No description provided')}
            Severity: {vulnerability.get('severity', 'Unknown')}
            Details: {vulnerability.get('details', 'No details provided')}
            
            Please provide:
            1. A clear explanation of what this vulnerability is
            2. Why it's a security concern
            3. How it could be exploited
            4. Recommended remediation steps
            5. Best practices to prevent this issue
            
            Format your response as a JSON object with these fields:
            - explanation: Main explanation of the vulnerability
            - risk: Description of the security risk
            - exploitation: How it could be exploited
            - remediation: Steps to fix the issue
            - prevention: Best practices to prevent this issue
            """
            
            if self.provider == "OpenAI" and self.client:
                # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
                # do not change this unless explicitly requested by the user
                response = self.client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity expert providing educational explanations about security vulnerabilities. Provide clear, actionable advice for security professionals."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    response_format={"type": "json_object"},
                    max_tokens=1500
                )
                explanation_data = json.loads(response.choices[0].message.content or "{}")
            else:
                # For other providers, return a structured response
                explanation_data = {
                    "explanation": f"AI explanation available with {self.provider} provider.",
                    "risk": f"Risk analysis for {vulnerability.get('title', 'Unknown')}",
                    "exploitation": "Exploitation details would be provided with full API integration.",
                    "remediation": "Remediation steps would be provided with full API integration.",
                    "prevention": "Prevention measures would be provided with full API integration."
                }
            
            # Format the explanation for display
            formatted_explanation = self._format_explanation(explanation_data)
            return formatted_explanation
            
        except Exception as e:
            return f"Unable to generate AI explanation: {str(e)}"
    
    def _format_explanation(self, explanation_data):
        """Format the AI explanation for display"""
        formatted = ""
        
        if "explanation" in explanation_data:
            formatted += f"**What is this vulnerability?**\n{explanation_data['explanation']}\n\n"
        
        if "risk" in explanation_data:
            formatted += f"**Security Risk:**\n{explanation_data['risk']}\n\n"
        
        if "exploitation" in explanation_data:
            formatted += f"**How it could be exploited:**\n{explanation_data['exploitation']}\n\n"
        
        if "remediation" in explanation_data:
            formatted += f"**How to fix it:**\n{explanation_data['remediation']}\n\n"
        
        if "prevention" in explanation_data:
            formatted += f"**Prevention:**\n{explanation_data['prevention']}\n\n"
        
        return formatted
    
    def generate_summary_report(self, findings):
        """Generate an AI-powered summary report of all findings"""
        if not self.client or not findings:
            return "No findings to summarize or AI not available."
        
        try:
            # Prepare findings summary
            findings_summary = []
            for finding in findings:
                findings_summary.append({
                    'title': finding.get('title', 'Unknown'),
                    'severity': finding.get('severity', 'Unknown'),
                    'description': finding.get('description', 'No description')
                })
            
            prompt = f"""
            Generate a comprehensive security assessment summary based on these findings:
            
            {json.dumps(findings_summary, indent=2)}
            
            Please provide:
            1. Executive summary of the security posture
            2. Key security concerns identified
            3. Risk assessment and prioritization
            4. High-level recommendations
            5. Overall security rating (1-10 scale)
            
            Format as JSON with fields: executive_summary, key_concerns, risk_assessment, recommendations, security_rating
            """
            
            # the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
            # do not change this unless explicitly requested by the user
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior cybersecurity consultant providing executive-level security assessments. Focus on business impact and strategic recommendations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                response_format={"type": "json_object"},
                max_tokens=2000
            )
            
            summary_data = json.loads(response.choices[0].message.content)
            return self._format_summary_report(summary_data)
            
        except Exception as e:
            return f"Unable to generate summary report: {str(e)}"
    
    def _format_summary_report(self, summary_data):
        """Format the AI summary report for display"""
        formatted = "## 🤖 AI-Powered Security Assessment Summary\n\n"
        
        if "executive_summary" in summary_data:
            formatted += f"### Executive Summary\n{summary_data['executive_summary']}\n\n"
        
        if "key_concerns" in summary_data:
            formatted += f"### Key Security Concerns\n{summary_data['key_concerns']}\n\n"
        
        if "risk_assessment" in summary_data:
            formatted += f"### Risk Assessment\n{summary_data['risk_assessment']}\n\n"
        
        if "recommendations" in summary_data:
            formatted += f"### Recommendations\n{summary_data['recommendations']}\n\n"
        
        if "security_rating" in summary_data:
            rating = summary_data['security_rating']
            formatted += f"### Security Rating\n**{rating}/10**\n\n"
        
        return formatted
