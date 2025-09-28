from flask import Flask, render_template, request, jsonify
import json
import os

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', 'dev-secret-key-please-change')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/xss-payloads')
def xss_payloads():
    return render_template('xss_payloads.html')

@app.route('/security-tools')
def security_tools():
    return render_template('security_tools.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/api/generate-command', methods=['POST'])
def generate_command():
    data = request.get_json()
    domain = data.get('domain', '')
    tool = data.get('tool', '')
    category = data.get('category', '')
    
    # Command generation logic will be implemented
    command = f"# Example command for {tool} on {domain}\necho 'Command generation coming soon'"
    
    return jsonify({'command': command})

@app.route('/api/generate-xss-payload', methods=['POST'])
def generate_xss_payload():
    data = request.get_json()
    context = data.get('context', 'html')
    encoding = data.get('encoding', 'none')
    category = data.get('category', 'basic')
    
    # XSS payload generation logic will be implemented
    payload = "<script>alert(1)</script>"
    
    return jsonify({'payload': payload})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)