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

@app.route('/extensions')
def extensions():
    return render_template('extensions.html')

@app.route('/api/generate-command', methods=['POST'])
def generate_command():
    data = request.get_json()
    domain = data.get('domain', '')
    tool_id = data.get('tool', '')
    category = data.get('category', '')
    
    # Load command templates
    try:
        with open('static/data/command_templates.json', 'r') as f:
            templates = json.load(f)
        
        # Find the tool in the category
        if category in templates:
            for tool in templates[category]['tools']:
                if tool['id'] == tool_id:
                    command = tool['command'].format(domain=domain)
                    return jsonify({'command': command, 'description': tool['description']})
        
        # Fallback
        command = f"# Command for {tool_id} on {domain}\necho 'Tool configuration not found'"
        return jsonify({'command': command})
        
    except Exception as e:
        return jsonify({'error': 'Failed to generate command'}), 500

@app.route('/api/command-templates')
def get_command_templates():
    try:
        with open('static/data/command_templates.json', 'r') as f:
            templates = json.load(f)
        return jsonify(templates)
    except Exception as e:
        return jsonify({'error': 'Failed to load command templates'}), 500

@app.route('/api/generate-xss-payload', methods=['POST'])
def generate_xss_payload():
    data = request.get_json()
    context = data.get('context', 'html')
    encoding = data.get('encoding', 'none')
    category = data.get('category', 'basic')
    callback_url = data.get('callback_url', '')
    
    try:
        with open('static/data/xss_payloads.json', 'r') as f:
            payload_data = json.load(f)
        
        # Get payloads for the specified category
        if category not in payload_data['categories']:
            return jsonify({'error': 'Invalid category'}), 400
        
        category_payloads = payload_data['categories'][category]['payloads']
        
        # Filter payloads by context (if not 'all')
        if context != 'all':
            filtered_payloads = [p for p in category_payloads if context in p.get('contexts', [])]
            if not filtered_payloads:
                # Fallback to any payload if no context-specific ones found
                filtered_payloads = category_payloads
        else:
            filtered_payloads = category_payloads
        
        # Apply encoding and callback URL substitution
        processed_payloads = []
        for payload in filtered_payloads:
            processed_payload = payload.copy()
            payload_text = payload['payload']
            
            # Replace callback URL placeholder
            if callback_url and '{{callback}}' in payload_text:
                payload_text = payload_text.replace('{{callback}}', callback_url)
            
            # Apply encoding
            if encoding != 'none':
                payload_text = apply_encoding(payload_text, encoding)
            
            processed_payload['payload'] = payload_text
            processed_payloads.append(processed_payload)
        
        return jsonify({
            'payloads': processed_payloads,
            'context_info': payload_data['contexts'].get(context, {}),
            'category_info': payload_data['categories'][category]
        })
        
    except Exception as e:
        return jsonify({'error': 'Failed to generate XSS payload'}), 500

def apply_encoding(payload, encoding):
    """Apply specified encoding to payload"""
    import urllib.parse
    import html
    
    if encoding == 'url':
        return urllib.parse.quote(payload)
    elif encoding == 'html':
        return html.escape(payload)
    elif encoding == 'unicode':
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    elif encoding == 'hex':
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    return payload

@app.route('/api/xss-payloads')
def get_xss_payloads():
    try:
        with open('static/data/xss_payloads.json', 'r') as f:
            payload_data = json.load(f)
        return jsonify(payload_data)
    except Exception as e:
        return jsonify({'error': 'Failed to load XSS payloads'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)