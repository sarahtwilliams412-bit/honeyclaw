#!/usr/bin/env python3
"""
Honey Claw - RDP Simulator
Simulates an RDP server for credential capture
"""

import socket
import json
import datetime
import os

HOST = '0.0.0.0'
PORT = 3389
LOG_FILE = '/var/log/honeypot/rdp.json'
HONEYPOT_ID = os.environ.get('HONEYPOT_ID', 'enterprise-sim')

def log_event(event):
    """Log event to JSON file"""
    event['timestamp'] = datetime.datetime.utcnow().isoformat() + 'Z'
    event['honeypot_id'] = HONEYPOT_ID
    event['service'] = 'rdp'
    
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')

def handle_connection(conn, addr):
    """Handle incoming RDP connection"""
    log_event({
        'event_type': 'connection',
        'source_ip': addr[0],
        'source_port': addr[1]
    })
    
    try:
        # Receive initial RDP negotiation request
        data = conn.recv(1024)
        
        if data:
            log_event({
                'event_type': 'negotiation',
                'source_ip': addr[0],
                'data_len': len(data),
                'data_hex': data[:64].hex()
            })
            
            # Send connection refused - but we got the attempt logged
            # In a real implementation, we'd simulate more of the protocol
            conn.close()
            
    except Exception as e:
        log_event({
            'event_type': 'error',
            'source_ip': addr[0],
            'error': str(e)
        })
    finally:
        conn.close()

def main():
    """Main RDP simulator loop"""
    print(f"[RDP Simulator] Starting on {HOST}:{PORT}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        
        while True:
            conn, addr = s.accept()
            print(f"[RDP] Connection from {addr[0]}:{addr[1]}")
            handle_connection(conn, addr)

if __name__ == '__main__':
    main()
