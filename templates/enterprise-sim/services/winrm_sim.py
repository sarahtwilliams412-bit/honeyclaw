#!/usr/bin/env python3
"""
Honey Claw - WinRM Simulator
Simulates Windows Remote Management for credential capture
"""

from flask import Flask, request, Response
import base64
import hashlib
import json
import datetime
import os
import sys

app = Flask(__name__)

PORT = 5985
LOG_FILE = '/var/log/honeypot/winrm.json'
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')
# Configurable salt for credential hashing - MUST be set in production
HASH_SALT = os.environ.get("HONEYCLAW_HASH_SALT", "")

def hash_credential(value: str) -> str:
    """Hash credential with salt for safe logging.
    
    Uses SHA256 with configurable salt. Returns first 16 chars of hex digest.
    Salt should be set via HONEYCLAW_HASH_SALT env var in production.
    """
    if not HASH_SALT:
        print("[WARN] HONEYCLAW_HASH_SALT not set - using unsalted hash", flush=True, file=sys.stderr)
    salted = f"{HASH_SALT}{value}".encode('utf-8')
    return hashlib.sha256(salted).hexdigest()[:16]

def extract_and_hash_basic_auth(auth_header: str) -> dict:
    """Extract Basic auth credentials and return hashed version.
    
    Returns dict with username (plain) and password_hash (hashed).
    Returns None if not Basic auth or parsing fails.
    """
    if not auth_header.startswith('Basic '):
        return None
    try:
        encoded = auth_header[6:]  # Strip 'Basic '
        decoded = base64.b64decode(encoded).decode('utf-8')
        if ':' in decoded:
            username, password = decoded.split(':', 1)
            return {
                'username': username,
                'password_hash': hash_credential(password),
                'password_length': len(password)
            }
    except Exception:
        pass
    return None

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'winrm'
    
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')

@app.before_request
def log_request():
    """Log all incoming requests (with sensitive headers redacted)"""
    # Redact headers that may contain credentials
    safe_headers = {}
    sensitive_headers = {'authorization', 'cookie', 'x-api-key', 'proxy-authorization'}
    for key, value in request.headers:
        if key.lower() in sensitive_headers:
            safe_headers[key] = '[REDACTED]'
        else:
            safe_headers[key] = value
    
    log_event({
        'event_type': 'request',
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'headers': safe_headers,
        'body': request.get_data(as_text=True)[:1024]
    })

@app.route('/wsman', methods=['POST'])
def wsman():
    """Handle WinRM SOAP requests"""
    # Check for NTLM/Kerberos auth headers
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header:
        event_data = {
            'event_type': 'auth_attempt',
            'source_ip': request.remote_addr,
        }
        
        # Check for Basic auth and hash credentials
        basic_creds = extract_and_hash_basic_auth(auth_header)
        if basic_creds:
            event_data['auth_type'] = 'basic'
            event_data['username'] = basic_creds['username']
            event_data['password_hash'] = basic_creds['password_hash']
            event_data['password_length'] = basic_creds['password_length']
        else:
            # For NTLM/Negotiate, just log the auth type (no raw tokens)
            if auth_header.startswith('Negotiate'):
                event_data['auth_type'] = 'negotiate'
            elif auth_header.startswith('NTLM'):
                event_data['auth_type'] = 'ntlm'
            else:
                event_data['auth_type'] = 'unknown'
            # Log token length only, not the token itself (could contain hashes)
            event_data['token_length'] = len(auth_header)
        
        log_event(event_data)
    
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
