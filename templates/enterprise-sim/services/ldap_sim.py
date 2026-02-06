#!/usr/bin/env python3
"""
Honey Claw - LDAP Simulator
Simulates Active Directory LDAP for enumeration detection
"""

import socket
import json
import datetime
import os
import struct

HOST = '0.0.0.0'
PORT = 389
LOG_FILE = '/var/log/honeypot/ldap.json'
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'ldap'
    
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')

def parse_ldap_message(data):
    """Basic LDAP message parsing"""
    # LDAP uses BER encoding - this is a simplified parser
    try:
        if len(data) < 2:
            return None
            
        # Check for LDAP sequence tag (0x30)
        if data[0] != 0x30:
            return None
            
        # Try to identify message type
        # BindRequest = 0x60, SearchRequest = 0x63, etc.
        msg_type = None
        for i, byte in enumerate(data):
            if byte == 0x60:
                msg_type = 'bind_request'
                break
            elif byte == 0x63:
                msg_type = 'search_request'
                break
            elif byte == 0x42:
                msg_type = 'unbind_request'
                break
                
        return {'type': msg_type, 'raw_len': len(data)}
        
    except Exception as e:
        return {'error': str(e)}

def handle_connection(conn, addr):
    """Handle incoming LDAP connection"""
    log_event({
        'event_type': 'connection',
        'source_ip': addr[0],
        'source_port': addr[1]
    })
    
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
                
            parsed = parse_ldap_message(data)
            
            log_event({
                'event_type': 'ldap_message',
                'source_ip': addr[0],
                'parsed': parsed,
                'data_hex': data[:128].hex()
            })
            
            # Send a generic LDAP error response
            # This is a minimal "operationsError" response
            error_response = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x01,  # messageID = 1
                0x61, 0x07,  # BindResponse
                0x0a, 0x01, 0x01,  # resultCode = operationsError
                0x04, 0x00,  # matchedDN = ""
                0x04, 0x00   # diagnosticMessage = ""
            ])
            conn.send(error_response)
            
    except Exception as e:
        log_event({
            'event_type': 'error',
            'source_ip': addr[0],
            'error': str(e)
        })
    finally:
        conn.close()

def main():
    """Main LDAP simulator loop"""
    print(f"[LDAP Simulator] Starting on {HOST}:{PORT}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            print(f"[LDAP] Connection from {addr[0]}:{addr[1]}")
            handle_connection(conn, addr)

if __name__ == '__main__':
    main()
