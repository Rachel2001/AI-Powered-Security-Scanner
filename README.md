# AI-Powered Security Scanner

A web-based tool that uses AI to scan text for potential phishing attempts and scams. The application leverages OpenAI's GPT model to analyze text and identify suspicious content.

## Features
- Text analysis for phishing attempts
- Scam detection
- AI-powered content analysis
- User-friendly web interface
- Detailed threat assessment

## Setup Instructions

1. Clone this repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file and add your OpenAI API key:
   ```
   OPENAI_API_KEY=your_api_key_here
   ```
5. Run the application:
   ```bash
   python app.py
   ```
6. Open http://localhost:5000 in your browser

## Note
You'll need an OpenAI API key to use this application. You can get one at https://platform.openai.com/ 