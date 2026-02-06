#!/usr/bin/env python3
"""
Honey Claw - WinRM Simulator
Simulates Windows Remote Management for credential capture
"""

from flask import Flask, request, Response
import json
import datetime
import os

app = Flask(__name__)

PORT = 5985
LOG_FILE = '/var/log/honeypot/winrm.json'
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'winrm'
    
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')

@app.before_request
def log_request():
    """Log all incoming requests"""
    log_event({
        'event_type': 'request',
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True)[:1024]
    })

@app.route('/wsman', methods=['POST'])
def wsman():
    """Handle WinRM SOAP requests"""
    # Check for NTLM/Kerberos auth headers
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header:
        log_event({
            'event_type': 'auth_attempt',
            'source_ip': request.remote_addr,
            'auth_header': auth_header[:256]
        })
    
    # Return 401 to prompt for credentials
    response = Response(
        '<?xml version="1.0" encoding="UTF-8"?><error>Unauthorized</error>',
        status=401,
        mimetype='application/xml'
    )
    response.headers['WWW-Authenticate'] = 'Negotiate'
    return response

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Catch all other requests"""
    return Response(status=404)

if __name__ == '__main__':
    print(f"[WinRM Simulator] Starting on port {PORT}")
    app.run(host='0.0.0.0', port=PORT)
