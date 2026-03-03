#!/usr/bin/env python3
import os
import sys
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import uuid
import hashlib
import hmac
from functools import wraps

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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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

# API keys storage (in production, use database)
api_keys = {}

# User sessions (in production, use database)
users = {}

# ==================== Helper Functions ====================

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_api_key(api_key):
    """Validate API key"""
    return api_key in api_keys

def generate_api_key(user_id):
    """Generate API key for user"""
    key = hashlib.sha256(f"{user_id}:{uuid.uuid4()}:{datetime.now()}".encode()).hexdigest()
    api_keys[key] = {'user_id': user_id, 'created': datetime.now()}
    return key

# ==================== Authentication Routes ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # In production, validate against database
        if username == 'admin' and password == 'admin':  # Change in production!
            session['user_id'] = str(uuid.uuid4())
            session['username'] = username
            session['role'] = 'admin'
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # In production, save to database
        user_id = str(uuid.uuid4())
        users[user_id] = {
            'username': username,
            'email': email,
            'password': hashlib.sha256(password.encode()).hexdigest(),  # Use proper hashing!
            'created': datetime.now()
        }
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html', user=users.get(session.get('user_id')))

@app.route('/api-keys')
@login_required
def api_keys_page():
    """API keys management page"""
    user_keys = [{'key': k, **v} for k, v in api_keys.items() 
                if v['user_id'] == session.get('user_id')]
    return render_template('api_keys.html', api_keys=user_keys)

@app.route('/generate-api-key', methods=['POST'])
@login_required
def generate_api_key_route():
    """Generate new API key"""
    api_key = generate_api_key(session['user_id'])
    flash('API key generated successfully', 'success')
    return redirect(url_for('api_keys_page'))

# ==================== Main Routes ====================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    # Get user's recent scans
    user_scans = [scan for scan_id, scan in active_scans.items() 
                 if scan.get('user_id') == session.get('user_id')]
    user_scans.sort(key=lambda x: x.get('start_time', ''), reverse=True)
    
    # Get completed scans
    completed_scans = [scan_results[scan_id] for scan_id in list(scan_results.keys())[:10]]
    
    return render_template('dashboard.html', 
                         active_scans=user_scans[:5],
                         completed_scans=completed_scans,
                         stats={
                             'total_scans': len(user_scans),
                             'completed': len([s for s in user_scans if s['status'] == 'completed']),
                             'threats': sum(1 for s in user_scans if s.get('threats_found', 0) > 0),
                             'uptime': '24h'  # Calculate actual uptime
                         })

@app.route('/scan-history')
@login_required
def scan_history():
    """View scan history"""
    user_scans = []
    for scan_id, scan in active_scans.items():
        if scan.get('user_id') == session.get('user_id'):
            result = scan_results.get(scan_id)
            user_scans.append({
                'id': scan_id,
                'tool': scan.get('tool_id'),
                'status': scan.get('status'),
                'start_time': scan.get('start_time'),
                'results': result
            })
    
    user_scans.sort(key=lambda x: x['start_time'], reverse=True)
    return render_template('scan_history.html', scans=user_scans)

# ==================== Tool Routes ====================

@app.route('/network')
@login_required
def network():
    """Network security tools"""
    return render_template('network.html', tools=[
        {'id': 'ddos', 'name': 'DDoS Attack Detector', 'description': 'Detect DDoS attacks in real-time', 'icon': 'fa-bolt'},
        {'id': 'arp', 'name': 'ARP Spoofing Detector', 'description': 'Detect ARP poisoning attacks', 'icon': 'fa-random'},
        {'id': 'sslstrip', 'name': 'SSL Strip Detector', 'description': 'Detect SSL stripping attacks', 'icon': 'fa-lock'},
        {'id': 'portscan', 'name': 'Port Scanner', 'description': 'Detect port scanning activities', 'icon': 'fa-search'},
        {'id': 'traffic', 'name': 'Traffic Analyzer', 'description': 'Analyze network traffic patterns', 'icon': 'fa-chart-line'}
    ])

@app.route('/webapp')
@login_required
def webapp():
    """Web application security tools"""
    return render_template('webapp.html', tools=[
        {'id': 'sqli', 'name': 'SQL Injection Scanner', 'description': 'Detect SQL injection vulnerabilities', 'icon': 'fa-database'},
        {'id': 'xss', 'name': 'XSS Detector', 'description': 'Detect Cross-Site Scripting vulnerabilities', 'icon': 'fa-code'},
        {'id': 'csrf', 'name': 'CSRF Tester', 'description': 'Test for CSRF vulnerabilities', 'icon': 'fa-exchange-alt'},
        {'id': 'waf', 'name': 'WAF Analyzer', 'description': 'Analyze Web Application Firewall rules', 'icon': 'fa-shield'}
    ])

@app.route('/malware')
@login_required
def malware():
    """Malware analysis tools"""
    return render_template('malware.html', tools=[
        {'id': 'ransomware', 'name': 'Ransomware Detector', 'description': 'Detect ransomware behavior', 'icon': 'fa-skull'},
        {'id': 'trojan', 'name': 'Trojan Scanner', 'description': 'Scan for trojans', 'icon': 'fa-bug'},
        {'id': 'rootkit', 'name': 'Rootkit Detector', 'description': 'Detect rootkits', 'icon': 'fa-ghost'},
        {'id': 'filemonitor', 'name': 'File Monitor', 'description': 'Monitor file system changes', 'icon': 'fa-file-alt'}
    ])

@app.route('/social')
@login_required
def social():
    """Social engineering tools"""
    return render_template('social.html', tools=[
        {'id': 'phishing', 'name': 'Phishing Detector', 'description': 'Detect phishing emails', 'icon': 'fa-envelope'},
        {'id': 'email', 'name': 'Email Analyzer', 'description': 'Analyze email headers and content', 'icon': 'fa-headers'},
        {'id': 'social', 'name': 'Social Engineering Detector', 'description': 'Detect social engineering attempts', 'icon': 'fa-users-cog'}
    ])

@app.route('/crypto')
@login_required
def crypto():
    """Cryptography tools"""
    return render_template('crypto.html', tools=[
        {'id': 'encrypt', 'name': 'Encryption Tools', 'description': 'Encrypt and decrypt data', 'icon': 'fa-lock'},
        {'id': 'hash', 'name': 'Hashing Tools', 'description': 'Generate and verify hashes', 'icon': 'fa-hashtag'},
        {'id': 'cert', 'name': 'Certificate Analyzer', 'description': 'Analyze SSL/TLS certificates', 'icon': 'fa-certificate'}
    ])

@app.route('/incident')
@login_required
def incident():
    """Incident response tools"""
    return render_template('incident.html', tools=[
        {'id': 'forensic', 'name': 'Forensic Analyzer', 'description': 'Analyze forensic evidence', 'icon': 'fa-microscope'},
        {'id': 'memory', 'name': 'Memory Analyzer', 'description': 'Analyze memory dumps', 'icon': 'fa-memory'},
        {'id': 'response', 'name': 'Incident Response', 'description': 'Incident response procedures', 'icon': 'fa-ambulance'}
    ])

# ==================== Tool-Specific Pages ====================

@app.route('/tool/<tool_id>')
@login_required
def tool_page(tool_id):
    """Generic tool page"""
    tool_mapping = {
        # Network tools
        'ddos': ('DDoS Attack Detector', 'network', 'ddos'),
        'arp': ('ARP Spoofing Detector', 'network', 'arp'),
        'sslstrip': ('SSL Strip Detector', 'network', 'sslstrip'),
        'portscan': ('Port Scanner', 'network', 'portscan'),
        'traffic': ('Traffic Analyzer', 'network', 'traffic'),
        
        # Web tools
        'sqli': ('SQL Injection Scanner', 'webapp', 'sqli'),
        'xss': ('XSS Detector', 'webapp', 'xss'),
        'csrf': ('CSRF Tester', 'webapp', 'csrf'),
        'waf': ('WAF Analyzer', 'webapp', 'waf'),
        
        # Malware tools
        'ransomware': ('Ransomware Detector', 'malware', 'ransomware'),
        'trojan': ('Trojan Scanner', 'malware', 'trojan'),
        'rootkit': ('Rootkit Detector', 'malware', 'rootkit'),
        'filemonitor': ('File Monitor', 'malware', 'filemonitor'),
        
        # Social tools
        'phishing': ('Phishing Detector', 'social', 'phishing'),
        'email': ('Email Analyzer', 'social', 'email'),
        'social': ('Social Engineering Detector', 'social', 'social'),
        
        # Crypto tools
        'encrypt': ('Encryption Tools', 'crypto', 'encrypt'),
        'hash': ('Hashing Tools', 'crypto', 'hash'),
        'cert': ('Certificate Analyzer', 'crypto', 'cert'),
        
        # Incident tools
        'forensic': ('Forensic Analyzer', 'incident', 'forensic'),
        'memory': ('Memory Analyzer', 'incident', 'memory'),
        'response': ('Incident Response', 'incident', 'response')
    }
    
    if tool_id not in tool_mapping:
        flash('Tool not found', 'danger')
        return redirect(url_for('dashboard'))
    
    name, category, template_id = tool_mapping[tool_id]
    return render_template('scanner.html', 
                         tool_id=tool_id,
                         tool_name=name,
                         tool_category=category,
                         tool_template=template_id)

# ==================== Scan Routes ====================

@app.route('/scan/start', methods=['POST'])
@login_required
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
        'user_id': session.get('user_id', 'anonymous'),
        'username': session.get('username', 'anonymous')
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
@login_required
def scan_status(scan_id):
    """Get scan status"""
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check ownership
    if scan.get('user_id') != session.get('user_id') and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan['status'],
        'progress': scan['progress'],
        'message': scan.get('message', '')
    })

@app.route('/scan/results/<scan_id>')
@login_required
def scan_results_page(scan_id):
    """Get scan results page"""
    scan = active_scans.get(scan_id)
    if not scan:
        flash('Scan not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Check ownership
    if scan.get('user_id') != session.get('user_id') and session.get('role') != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    results = scan_results.get(scan_id)
    if not results:
        flash('Results not ready yet', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('results.html', 
                         scan_id=scan_id,
                         results=results,
                         tool_id=results.get('tool_id', scan.get('tool_id')),
                         scan_info=scan)

@app.route('/scan/export/<scan_id>')
@login_required
def export_scan(scan_id):
    """Export scan results"""
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    format_type = request.args.get('format', 'json')
    
    if format_type == 'json':
        return jsonify(results)
    elif format_type == 'csv':
        # Generate CSV
        import csv
        from io import StringIO
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow(['Key', 'Value'])
        for key, value in results.items():
            cw.writerow([key, json.dumps(value)])
        return si.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=scan_{scan_id}.csv'
        }
    elif format_type == 'pdf':
        # PDF generation would go here
        flash('PDF export coming soon', 'info')
        return redirect(url_for('scan_results_page', scan_id=scan_id))
    
    return jsonify({'error': 'Invalid format'}), 400

@app.route('/scan/cancel/<scan_id>', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    scan = active_scans.get(scan_id)
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check ownership
    if scan.get('user_id') != session.get('user_id') and session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if scan_id in active_scans:
        active_scans[scan_id]['status'] = 'cancelled'
        return jsonify({'success': True, 'message': 'Scan cancelled'})
    
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/scan/save/<scan_id>', methods=['POST'])
@login_required
def save_scan(scan_id):
    """Save scan result to user's history"""
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    # In production, save to database
    flash('Scan saved successfully', 'success')
    return jsonify({'success': True})

# ==================== File Upload ====================

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Handle file uploads for scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'File too large'}), 413
    
    # Secure filename and save
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)
    
    # Calculate file hash
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()
    
    return jsonify({
        'success': True,
        'filename': filename,
        'filepath': filepath,
        'file_id': unique_filename,
        'size': file_size,
        'hash': file_hash
    })

# ==================== API Dashboard Routes ====================

@app.route('/api/v1/dashboard/stats')
@login_required
def api_dashboard_stats():
    """Get dashboard statistics"""
    user_scans = [s for s in active_scans.values() if s.get('user_id') == session.get('user_id')]
    
    return jsonify({
        'active_scans': len([s for s in user_scans if s['status'] == 'running']),
        'completed_scans': len([s for s in user_scans if s['status'] == 'completed']),
        'threats_found': sum(1 for s in user_scans if s.get('threats_found', 0) > 0),
        'uptime': '24h',
        'cpu': 45,  # Get actual CPU usage
        'memory': 60,  # Get actual memory usage
        'disk': 55,  # Get actual disk usage
        'network': 30  # Get actual network I/O
    })

@app.route('/api/v1/scans/recent')
@login_required
def api_recent_scans():
    """Get recent scans"""
    user_scans = []
    for scan_id, scan in active_scans.items():
        if scan.get('user_id') == session.get('user_id'):
            user_scans.append({
                'id': scan_id,
                'tool_name': scan.get('tool_id'),
                'target': scan.get('parameters', {}).get('url', scan.get('parameters', {}).get('target', 'N/A')),
                'status': scan.get('status'),
                'date': scan.get('start_time')
            })
    
    user_scans.sort(key=lambda x: x['date'], reverse=True)
    return jsonify({'scans': user_scans[:10]})

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
        }, room=scan_id)
        
        # Route to appropriate scanner
        if tool_id == 'ddos':
            results = run_ddos_scan(scan_id, parameters)
        elif tool_id == 'sqli':
            results = run_sqli_scan(scan_id, parameters)
        elif tool_id == 'phishing':
            results = run_phishing_scan(scan_id, parameters)
        elif tool_id == 'ransomware':
            results = run_ransomware_scan(scan_id, parameters)
        elif tool_id == 'portscan':
            results = run_portscan_scan(scan_id, parameters)
        elif tool_id == 'arp':
            results = run_arp_scan(scan_id, parameters)
        else:
            results = {'error': f'Unknown tool: {tool_id}'}
        
        # Store results
        scan_results[scan_id] = results
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['progress'] = 100
        active_scans[scan_id]['threats_found'] = results.get('threats_found', 0)
        
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'results': results
        }, room=scan_id)
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)
        
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'error': str(e)
        }, room=scan_id)

def run_ddos_scan(scan_id, parameters):
    """Run DDoS detection scan"""
    detector = DDoSDetector()
    
    # Update progress using scan_id
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Capturing traffic...'
    }, room=scan_id)
    
    # Run detection
    results = detector.analyze_traffic(
        interface=parameters.get('interface', 'eth0'),
        duration=parameters.get('duration', 60)
    )
    
    return results

def run_sqli_scan(scan_id, parameters):
    """Run SQL injection scan"""
    scanner = SQLInjectionScanner()
    
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Scanning URL for SQL injection...'
    }, room=scan_id)
    
    results = scanner.scan_url(
        url=parameters.get('url'),
        depth=parameters.get('depth', 2)
    )
    
    return results

def run_phishing_scan(scan_id, parameters):
    """Run phishing detection scan"""
    detector = PhishingDetector()
    
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Analyzing for phishing indicators...'
    }, room=scan_id)
    
    if 'email_file' in parameters:
        results = detector.analyze_email_file(parameters['email_file'])
    elif 'url' in parameters:
        results = detector.analyze_url(parameters['url'])
    else:
        results = {'error': 'No input provided'}
    
    return results

def run_ransomware_scan(scan_id, parameters):
    """Run ransomware detection scan"""
    detector = RansomwareDetector()
    
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Scanning for ransomware behavior...'
    }, room=scan_id)
    
    results = detector.scan_system(
        paths=parameters.get('paths', ['/home', 'C:\\Users']),
        quick=parameters.get('quick', True)
    )
    
    return results

def run_portscan_scan(scan_id, parameters):
    """Run port scan"""
    detector = PortScanDetector()
    
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Scanning ports...'
    }, room=scan_id)
    
    results = detector.scan_ports(
        target=parameters.get('target', 'localhost'),
        ports=parameters.get('ports', '1-1024')
    )
    
    return results

def run_arp_scan(scan_id, parameters):
    """Run ARP spoofing detection"""
    detector = ARPSpoofDetector()
    
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'progress': 30,
        'message': 'Monitoring ARP traffic...'
    }, room=scan_id)
    
    results = detector.detect_spoofing(
        interface=parameters.get('interface', 'eth0'),
        duration=parameters.get('duration', 60)
    )
    
    return results

# ==================== API Routes ====================

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning"""
    data = request.json
    
    # Validate API key
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
    # Validate API key
    api_key = request.headers.get('X-API-Key')
    if not validate_api_key(api_key):
        return jsonify({'error': 'Invalid API key'}), 401
    
    results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(results)

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
        # Join a room for this scan
        from flask_socketio import join_room
        join_room(scan_id)
        emit('subscribed', {'scan_id': scan_id})
        logger.info(f"Client {request.sid} subscribed to scan {scan_id}")

@socketio.on('unsubscribe')
def handle_unsubscribe(data):
    """Unsubscribe from scan updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        from flask_socketio import leave_room
        leave_room(scan_id)
        emit('unsubscribed', {'scan_id': scan_id})

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
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
    logger.info(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    logger.info(f"Access the application at: http://localhost:{port}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )
