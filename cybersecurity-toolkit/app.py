import os
import sys
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import json
import uuid

# Import configuration
from config import config

# Import modules
from modules.network import (
    DDoSDetector, ARPSpoofDetector, SSLStripDetector,
    PortScanDetector, TrafficAnalyzer
)
from modules.webapp import (
    SQLInjectionScanner, XSSDetector, CSFRTester,
    WAFAnalyzer
)
from modules.malware import (
    RansomwareDetector, TrojanScanner, RootkitDetector,
    FileMonitor
)
from modules.social import (
    PhishingDetector, EmailAnalyzer, SocialEngineDetector
)
from modules.crypto import (
    EncryptionTools, HashingTools
)
from modules.incident import (
    ForensicAnalyzer, MemoryAnalyzer, IncidentResponse
)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(config[os.environ.get('FLASK_ENV', 'default')])

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cybersecurity.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store active scans (in production, use Redis)
active_scans = {}
scan_results = {}

# ==================== Routes ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/network')
def network():
    """Network security tools"""
    return render_template('network.html', tools=[
        {'id': 'ddos', 'name': 'DDoS Attack Detector', 'description': 'Detect DDoS attacks in real-time'},
        {'id': 'arp', 'name': 'ARP Spoofing Detector', 'description': 'Detect ARP poisoning attacks'},
        {'id': 'sslstrip', 'name': 'SSL Strip Detector', 'description': 'Detect SSL stripping attacks'},
        {'id': 'portscan', 'name': 'Port Scanner', 'description': 'Detect port scanning activities'},
        {'id': 'traffic', 'name': 'Traffic Analyzer', 'description': 'Analyze network traffic patterns'}
    ])

@app.route('/webapp')
def webapp():
    """Web application security tools"""
    return render_template('webapp.html', tools=[
        {'id': 'sqli', 'name': 'SQL Injection Scanner', 'description': 'Detect SQL injection vulnerabilities'},
        {'id': 'xss', 'name': 'XSS Detector', 'description': 'Detect Cross-Site Scripting vulnerabilities'},
        {'id': 'csrf', 'name': 'CSRF Tester', 'description': 'Test for CSRF vulnerabilities'},
        {'id': 'waf', 'name': 'WAF Analyzer', 'description': 'Analyze Web Application Firewall rules'}
    ])

@app.route('/malware')
def malware():
    """Malware analysis tools"""
    return render_template('malware.html', tools=[
        {'id': 'ransomware', 'name': 'Ransomware Detector', 'description': 'Detect ransomware behavior'},
        {'id': 'trojan', 'name': 'Trojan Scanner', 'description': 'Scan for trojans'},
        {'id': 'rootkit', 'name': 'Rootkit Detector', 'description': 'Detect rootkits'},
        {'id': 'filemonitor', 'name': 'File Monitor', 'description': 'Monitor file system changes'}
    ])

@app.route('/social')
def social():
    """Social engineering tools"""
    return render_template('social.html', tools=[
        {'id': 'phishing', 'name': 'Phishing Detector', 'description': 'Detect phishing emails'},
        {'id': 'email', 'name': 'Email Analyzer', 'description': 'Analyze email headers and content'},
        {'id': 'social', 'name': 'Social Engineering Detector', 'description': 'Detect social engineering attempts'}
    ])

@app.route('/crypto')
def crypto():
    """Cryptography tools"""
    return render_template('crypto.html', tools=[
        {'id': 'encrypt', 'name': 'Encryption Tools', 'description': 'Encrypt and decrypt data'},
        {'id': 'hash', 'name': 'Hashing Tools', 'description': 'Generate and verify hashes'},
        {'id': 'cert', 'name': 'Certificate Analyzer', 'description': 'Analyze SSL/TLS certificates'}
    ])

@app.route('/incident')
def incident():
    """Incident response tools"""
    return render_template('incident.html', tools=[
        {'id': 'forensic', 'name': 'Forensic Analyzer', 'description': 'Analyze forensic evidence'},
        {'id': 'memory', 'name': 'Memory Analyzer', 'description': 'Analyze memory dumps'},
        {'id': 'response', 'name': 'Incident Response', 'description': 'Incident response procedures'}
    ])

# ==================== Scan Routes ====================

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    tool_id = data.get('tool_id')
    parameters = data.get('parameters', {})
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Store scan info
    active_scans[scan_id] = {
        'id': scan_id,
        'tool_id': tool_id,
        'parameters': parameters,
        'status': 'starting',
        'progress': 0,
        'start_time': datetime.now().isoformat(),
        'user_id': session.get('user_id', 'anonymous')
    }
    
    # Start scan in background
    socketio.start_background_task(
        target=run_scan,
        scan_id=scan_id,
        tool_id=tool_id,
        parameters=parameters
    )
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'status': 'started'
    })

@app.route('/scan/status/<scan_id>')
def scan_status(scan_id):
    """Get scan status"""
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan['status'],
        'progress': scan['progress'],
        'message': scan.get('message', '')
    })

@app.route('/scan/results/<scan_id>')
def scan_results(scan_id):
    """Get scan results"""
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    return render_template('results.html', 
                         scan_id=scan_id,
                         results=results,
                         tool_id=results.get('tool_id'))

@app.route('/scan/cancel/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel a running scan"""
    if scan_id in active_scans:
        active_scans[scan_id]['status'] = 'cancelled'
        return jsonify({'success': True, 'message': 'Scan cancelled'})
    return jsonify({'error': 'Scan not found'}), 404

# ==================== File Upload ====================

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads for scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Secure filename and save
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'filename': filename,
        'filepath': filepath,
        'file_id': unique_filename
    })

# ==================== Scan Functions ====================

def run_scan(scan_id, tool_id, parameters):
    """Run a scan in the background"""
    try:
        active_scans[scan_id]['status'] = 'running'
        
        # Update progress
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'progress': 10,
            'message': 'Initializing scan...'
        })
        
        # Route to appropriate scanner
        if tool_id == 'ddos':
            results = run_ddos_scan(parameters)
        elif tool_id == 'sqli':
            results = run_sqli_scan(parameters)
        elif tool_id == 'phishing':
            results = run_phishing_scan(parameters)
        elif tool_id == 'ransomware':
            results = run_ransomware_scan(parameters)
        else:
            results = {'error': f'Unknown tool: {tool_id}'}
        
        # Store results
        scan_results[scan_id] = results
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)
        
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': str(e)
        })

def run_ddos_scan(parameters):
    """Run DDoS detection scan"""
    detector = DDoSDetector()
    
    # Update progress
    socketio.emit('scan_update', {
        'scan_id': request.args.get('scan_id'),
        'progress': 30,
        'message': 'Capturing traffic...'
    })
    
    # Run detection
    results = detector.analyze_traffic(
        interface=parameters.get('interface', 'eth0'),
        duration=parameters.get('duration', 60)
    )
    
    return results

def run_sqli_scan(parameters):
    """Run SQL injection scan"""
    scanner = SQLInjectionScanner()
    
    results = scanner.scan_url(
        url=parameters.get('url'),
        depth=parameters.get('depth', 2)
    )
    
    return results

def run_phishing_scan(parameters):
    """Run phishing detection scan"""
    detector = PhishingDetector()
    
    if 'email_file' in parameters:
        results = detector.analyze_email_file(parameters['email_file'])
    elif 'url' in parameters:
        results = detector.analyze_url(parameters['url'])
    else:
        results = {'error': 'No input provided'}
    
    return results

def run_ransomware_scan(parameters):
    """Run ransomware detection scan"""
    detector = RansomwareDetector()
    
    results = detector.scan_system(
        paths=parameters.get('paths', ['/home', 'C:\\Users']),
        quick=parameters.get('quick', True)
    )
    
    return results

# ==================== API Routes ====================

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning"""
    data = request.json
    
    # Validate API key (implement your own validation)
    api_key = request.headers.get('X-API-Key')
    if not validate_api_key(api_key):
        return jsonify({'error': 'Invalid API key'}), 401
    
    scan_id = str(uuid.uuid4())
    
    # Start scan in background
    socketio.start_background_task(
        target=run_scan,
        scan_id=scan_id,
        tool_id=data.get('tool_id'),
        parameters=data.get('parameters', {})
    )
    
    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'status_url': f'/api/v1/scan/{scan_id}'
    })

@app.route('/api/v1/scan/<scan_id>', methods=['GET'])
def api_get_scan(scan_id):
    """Get scan results via API"""
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(results)

def validate_api_key(api_key):
    """Validate API key"""
    # Implement your API key validation
    return True  # Placeholder

# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        emit('subscribed', {'scan_id': scan_id})

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large_error(error):
    return jsonify({'error': 'File too large'}), 413

# ==================== Main Entry Point ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = app.config['DEBUG']
    
    logger.info(f"Starting Cybersecurity Toolkit on port {port}")
    logger.info(f"Debug mode: {debug}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )
