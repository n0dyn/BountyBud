from flask import Flask, render_template, request, jsonify
import json
import os
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', 'dev-secret-key-please-change')

# Callback storage file
CALLBACKS_FILE = 'static/data/xss_callbacks.json'

def ensure_callbacks_file():
    """Ensure callbacks JSON file exists"""
    Path('static/data').mkdir(parents=True, exist_ok=True)
    if not os.path.exists(CALLBACKS_FILE):
        with open(CALLBACKS_FILE, 'w') as f:
            json.dump({'callbacks': []}, f)

def load_callbacks():
    """Load all logged callbacks"""
    ensure_callbacks_file()
    try:
        with open(CALLBACKS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {'callbacks': []}

def save_callbacks(data):
    """Save callbacks to file"""
    ensure_callbacks_file()
    with open(CALLBACKS_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_request_domain():
    """Get the current request domain for callback URLs"""
    if request.host_url:
        return request.host_url.rstrip('/')
    return 'http://localhost:5000'

# Add cache control headers to prevent caching issues in deployment
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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

@app.route('/xss-callbacks')
def xss_callbacks():
    return render_template('xss_callbacks.html')

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

@app.route('/api/xss-callback/<callback_id>', methods=['GET', 'POST'])
def xss_callback(callback_id):
    """Receive callback from blind XSS payload execution"""
    try:
        # Collect callback information
        callback_data = {
            'id': callback_id,
            'timestamp': datetime.utcnow().isoformat(),
            'method': request.method,
            'remote_addr': request.remote_addr,
            'headers': dict(request.headers),
            'query_params': dict(request.args),
            'cookies': dict(request.cookies),
            'user_agent': request.user_agent.string,
        }
        
        # Include body data if present
        if request.method == 'POST':
            try:
                if request.is_json:
                    callback_data['body'] = request.get_json()
                else:
                    callback_data['body'] = request.get_data(as_text=True)
            except:
                callback_data['body'] = request.get_data(as_text=True)
        
        # Load existing callbacks
        data = load_callbacks()
        data['callbacks'].append(callback_data)
        
        # Keep only last 100 callbacks
        if len(data['callbacks']) > 100:
            data['callbacks'] = data['callbacks'][-100:]
        
        save_callbacks(data)
        
        # Return confirmation
        return jsonify({
            'success': True,
            'message': 'Callback received and logged',
            'callback_id': callback_id,
            'timestamp': callback_data['timestamp']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/xss-callbacks')
def get_xss_callbacks():
    """Get all logged XSS callbacks"""
    try:
        data = load_callbacks()
        return jsonify({
            'callbacks': data['callbacks'],
            'total': len(data['callbacks'])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/xss-callbacks/clear', methods=['POST'])
def clear_xss_callbacks():
    """Clear all logged callbacks"""
    try:
        save_callbacks({'callbacks': []})
        return jsonify({'success': True, 'message': 'Callbacks cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Development server configuration
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)