from flask import Flask, request, jsonify, render_template
import uuid
import os
import json
from datetime import datetime

app = Flask(__name__, 
            template_folder='../templates',
            static_folder='../static')

# Remove SocketIO completely
# Store scan results in memory (temporary)
scan_results = {}

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/tools', methods=['GET'])
def list_tools():
    """List all available tools"""
    tools = {
        'network': [
            {'id': 'ddos', 'name': 'DDoS Detector', 'description': 'Detect DDoS attacks'},
            {'id': 'portscan', 'name': 'Port Scanner', 'description': 'Scan for open ports'}
        ],
        'webapp': [
            {'id': 'sqli', 'name': 'SQL Injection Scanner', 'description': 'Find SQL vulnerabilities'},
            {'id': 'xss', 'name': 'XSS Detector', 'description': 'Find XSS vulnerabilities'}
        ]
    }
    return jsonify(tools)

@app.route('/api/scan', methods=['POST'])
def scan():
    """Run a scan (synchronous for Vercel)"""
    try:
        data = request.json
        tool_id = data.get('tool_id')
        params = data.get('parameters', {})
        
        scan_id = str(uuid.uuid4())
        
        # Simulate different scans (keep under 9 seconds!)
        if tool_id == 'ddos':
            result = simulate_ddos_scan(params)
        elif tool_id == 'sqli':
            result = simulate_sqli_scan(params)
        elif tool_id == 'portscan':
            result = simulate_port_scan(params)
        else:
            result = {'error': f'Unknown tool: {tool_id}'}
        
        # Store result
        scan_results[scan_id] = {
            'id': scan_id,
            'tool': tool_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'result': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan results"""
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

def simulate_ddos_scan(params):
    """Simulate DDoS detection"""
    import random
    return {
        'threat_level': random.choice(['LOW', 'MEDIUM', 'HIGH']),
        'packet_rate': random.randint(100, 10000),
        'findings': [
            'SYN flood detected' if random.random() > 0.5 else None,
            'UDP amplification' if random.random() > 0.7 else None
        ],
        'recommendations': [
            'Enable rate limiting',
            'Configure firewall rules',
            'Use CDN services'
        ]
    }

def simulate_sqli_scan(params):
    """Simulate SQL injection scan"""
    import random
    url = params.get('url', 'unknown')
    return {
        'url': url,
        'vulnerable': random.choice([True, False]),
        'parameters_tested': 15,
        'vulnerabilities_found': random.randint(0, 3),
        'risk_level': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
        'details': [
            {'parameter': 'id', 'type': 'boolean-based', 'payload': "' OR '1'='1"}
        ] if random.random() > 0.5 else []
    }

def simulate_port_scan(params):
    """Simulate port scan"""
    import random
    target = params.get('target', 'localhost')
    open_ports = random.sample(range(1, 1024), random.randint(0, 10))
    return {
        'target': target,
        'ports_scanned': 1024,
        'open_ports': open_ports,
        'services': [
            {'port': 80, 'service': 'HTTP', 'banner': 'Apache/2.4.41'},
            {'port': 22, 'service': 'SSH', 'banner': 'OpenSSH/8.2p1'}
        ] if open_ports else []
    }

# Vercel handler
def handler(request):
    """Vercel serverless function handler"""
    with app.request_context(request):
        return app.full_dispatch_request()

# For local development
if __name__ == '__main__':
    app.run(debug=True, port=5000)
