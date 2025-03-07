from flask import Flask, render_template, request, jsonify
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import openai
import os
import re

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
csrf = CSRFProtect(app)

# Configure OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

def check_phishing_indicators(text):
    """
    Rule-based system to check for common phishing and scam indicators
    """
    indicators = []
    threat_level = "Low"
    
    # Common phishing keywords and patterns
    urgent_words = ['urgent', 'immediate', 'action required', 'account suspended', 'verify your account']
    financial_words = ['bank', 'paypal', 'credit card', 'western union', 'money transfer', 'won', 'lottery', 'prize']
    threat_words = ['suspended', 'disabled', 'blocked', 'unauthorized', 'suspicious activity']
    
    # Check for suspicious URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text.lower())
    if urls:
        for url in urls:
            if any(brand in url.lower() for brand in ['amazon', 'paypal', 'bank', 'netflix']):
                if any(suspicious in url.lower() for suspicious in ['-secure', '.net-', 'login', 'verify']):
                    indicators.append("⚠️ Suspicious URL detected that mimics a legitimate service")
                    threat_level = "High"

    # Check for urgency and pressure tactics
    if any(word.lower() in text.lower() for word in urgent_words):
        indicators.append("⚠️ Urgency or pressure tactics detected")
        threat_level = max(threat_level, "Medium")

    # Check for financial scam indicators
    if any(word.lower() in text.lower() for word in financial_words):
        if 'send' in text.lower() or 'fee' in text.lower() or 'processing' in text.lower():
            indicators.append("⚠️ Potential financial scam detected")
            threat_level = "High"

    # Check for account threat indicators
    if any(word.lower() in text.lower() for word in threat_words):
        indicators.append("⚠️ Account security threat language detected")
        threat_level = max(threat_level, "Medium")

    # Check for personal information requests
    if any(word in text.lower() for word in ['ssn', 'social security', 'password', 'credit card number']):
        indicators.append("⚠️ Requests for sensitive personal information detected")
        threat_level = "High"

    # Check for poor grammar and spelling
    if len(re.findall(r'\b(ur|u|plz|pls)\b', text.lower())) > 0:
        indicators.append("⚠️ Unprofessional language or poor grammar detected")
        threat_level = max(threat_level, "Medium")

    # If no threats detected
    if not indicators:
        indicators.append("✅ No immediate security threats detected")
        threat_level = "Low"

    return {
        'threat_level': threat_level,
        'indicators': indicators
    }

def format_analysis_response(analysis_result):
    """
    Format the analysis results into a readable markdown response
    """
    threat_level = analysis_result['threat_level']
    indicators = analysis_result['indicators']
    
    emoji_map = {
        "High": "🚨",
        "Medium": "⚠️",
        "Low": "✅"
    }
    
    response = f"## Security Analysis {emoji_map.get(threat_level, '❓')}\n\n"
    response += f"### Threat Level: {threat_level}\n\n"
    response += "### Findings:\n"
    for indicator in indicators:
        response += f"- {indicator}\n"
    
    if threat_level == "High":
        response += "\n### 🛑 ALERT: This message shows strong indicators of being a potential scam or phishing attempt. Do not click any links or provide any personal information!"
    elif threat_level == "Medium":
        response += "\n### ⚠️ CAUTION: This message shows some suspicious characteristics. Proceed with caution and verify through official channels."
    else:
        response += "\n### ✅ This message appears to be relatively safe, but always remain vigilant."
    
    return response

def analyze_text(text):
    """
    Analyze text using OpenAI's GPT model for security threats with fallback to rule-based system
    """
    try:
        # Try AI analysis first
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing text for potential phishing attempts, scams, or malicious content. Provide a detailed analysis with threat level (Low, Medium, High) and specific concerns identified."},
                {"role": "user", "content": f"Analyze this text for potential security threats: {text}"}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return response.choices[0].message.content
    except Exception as e:
        # Fallback to rule-based analysis
        analysis_result = check_phishing_indicators(text)
        return format_analysis_response(analysis_result)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    text = request.form.get('text', '')
    if not text:
        return jsonify({'error': 'No text provided'})
    
    analysis = analyze_text(text)
    return jsonify({'analysis': analysis})

if __name__ == '__main__':
    app.run(debug=True) 