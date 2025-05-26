from flask import Flask, render_template, request, jsonify, send_file
from scanner import VulnerabilityScanner
from report_generator import ReportGenerator
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Validate target format
    if not (target.replace('.', '').isdigit() or '.' in target):
        return jsonify({'error': 'Invalid target format'}), 400
    
    # Basic rate limiting
    if not hasattr(app, 'scan_count'):
        app.scan_count = 0
    app.scan_count += 1
    
    if app.scan_count > 10:  # Limit to 10 scans per session
        return jsonify({'error': 'Scan limit reached. Please try again later.'}), 429
    
    scanner = VulnerabilityScanner()
    results = scanner.scan(target, scan_type)
    
    # Generate report
    report_gen = ReportGenerator()
    report_path = report_gen.generate_report(results, target)
    
    return jsonify({
        'status': 'success',
        'results': results,
        'report_path': report_path
    })

@app.route('/download-report/<path:filename>')
def download_report(filename):
    # Add security check for filename
    if not filename.startswith('reports/'):
        return jsonify({'error': 'Invalid file path'}), 400
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug) 