#!/usr/bin/env python3
"""
Honey Claw - Input Validation Utilities
Defensive validation for all attacker-supplied input.

SECURITY: Honeypots receive malicious input by design.
All data must be sanitized before logging or processing.
"""

import re
import string
from typing import Optional, Tuple

# === Size Limits ===
MAX_USERNAME_LENGTH = 256
MAX_PASSWORD_LENGTH = 1024
MAX_COMMAND_LENGTH = 4096
MAX_PATH_LENGTH = 4096
MAX_HEADER_LENGTH = 8192
MAX_BODY_LENGTH = 65536  # 64KB
MAX_HEX_LOG_LENGTH = 256  # bytes to hex-encode for logging
MAX_RAW_LOG_LENGTH = 1024
MAX_LOG_LINE_LENGTH = 16384  # 16KB per log line

# === Character Whitelists ===
# Printable ASCII minus control chars and some dangerous ones
SAFE_USERNAME_CHARS = set(string.ascii_letters + string.digits + "._-@+")
SAFE_PATH_CHARS = set(string.ascii_letters + string.digits + "/_.-")
PRINTABLE_SAFE = set(string.printable) - set('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f')

# Shell metacharacters to escape
SHELL_METACHARACTERS = set(';&|`$(){}[]<>\\\'\"!#~*?')


def validate_username(username: Optional[str], max_length: int = MAX_USERNAME_LENGTH) -> Tuple[str, bool]:
    """
    Validate and sanitize username input.
    
    Returns:
        Tuple of (sanitized_username, is_valid)
        - sanitized_username: Safe version for logging
        - is_valid: Whether original was within normal bounds
    """
    if username is None:
        return "<null>", False
    
    if not isinstance(username, str):
        return "<invalid-type>", False
    
    # Length check
    is_valid = len(username) <= max_length
    
    # Truncate for safety
    username = username[:max_length]
    
    # Remove null bytes and control characters
    sanitized = ''.join(c if c in SAFE_USERNAME_CHARS else '_' for c in username)
    
    # Empty after sanitization?
    if not sanitized:
        sanitized = "<empty>"
        is_valid = False
    
    return sanitized, is_valid


def validate_password(password: Optional[str], max_length: int = MAX_PASSWORD_LENGTH) -> Tuple[int, bool]:
    """
    Validate password - we never log the actual password, just metadata.
    
    Returns:
        Tuple of (password_length, is_valid)
    """
    if password is None:
        return 0, True
    
    if not isinstance(password, str):
        return -1, False
    
    # Check if within bounds
    is_valid = len(password) <= max_length
    
    # Return length (capped) for logging
    return min(len(password), max_length), is_valid


def sanitize_for_log(text: Optional[str], max_length: int = MAX_RAW_LOG_LENGTH) -> str:
    """
    Sanitize arbitrary text for safe logging.
    Removes control characters and truncates.
    """
    if text is None:
        return "<null>"
    
    if not isinstance(text, str):
        try:
            text = str(text)
        except:
            return "<unconvertible>"
    
    # Truncate first to limit processing
    text = text[:max_length]
    
    # Replace non-printable with escaped representation
    result = []
    for c in text:
        if c in PRINTABLE_SAFE:
            result.append(c)
        elif c == '\n':
            result.append('\\n')
        elif c == '\r':
            result.append('\\r')
        elif c == '\t':
            result.append('\\t')
        else:
            result.append(f'\\x{ord(c):02x}')
    
    sanitized = ''.join(result)
    
    # Final length check after escaping
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length - 3] + '...'
    
    return sanitized


def sanitize_path(path: Optional[str], max_length: int = MAX_PATH_LENGTH) -> Tuple[str, bool]:
    """
    Validate and sanitize file/URL path.
    
    Returns:
        Tuple of (sanitized_path, is_valid)
    """
    if path is None:
        return "/", True
    
    if not isinstance(path, str):
        return "<invalid>", False
    
    is_valid = len(path) <= max_length
    path = path[:max_length]
    
    # Remove path traversal attempts for logging
    sanitized = path.replace('../', '_parent_/')
    sanitized = sanitized.replace('..\\', '_parent_\\')
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    return sanitized, is_valid


def sanitize_headers(headers: dict, max_header_len: int = MAX_HEADER_LENGTH) -> dict:
    """
    Sanitize HTTP headers for logging.
    Truncates values and removes dangerous content.
    """
    if not isinstance(headers, dict):
        return {"_error": "invalid-headers-type"}
    
    safe_headers = {}
    for key, value in headers.items():
        # Sanitize key
        safe_key = sanitize_for_log(str(key), max_length=256)
        
        # Sanitize value
        if isinstance(value, str):
            safe_value = sanitize_for_log(value, max_length=max_header_len)
        else:
            safe_value = sanitize_for_log(str(value), max_length=max_header_len)
        
        safe_headers[safe_key] = safe_value
        
        # Limit total headers
        if len(safe_headers) >= 50:
            safe_headers["_truncated"] = True
            break
    
    return safe_headers


def sanitize_body(body: Optional[str], max_length: int = MAX_BODY_LENGTH) -> str:
    """
    Sanitize request body for logging.
    """
    if body is None:
        return ""
    
    return sanitize_for_log(body, max_length=max_length)


def escape_shell(command: Optional[str], max_length: int = MAX_COMMAND_LENGTH) -> str:
    """
    Escape shell metacharacters for safe logging/display.
    NOT for executing - honeypots shouldn't execute attacker commands.
    """
    if command is None:
        return ""
    
    if not isinstance(command, str):
        return "<invalid>"
    
    command = command[:max_length]
    
    # Escape metacharacters
    result = []
    for c in command:
        if c in SHELL_METACHARACTERS:
            result.append('\\')
        result.append(c)
    
    return ''.join(result)


def safe_hex(data: bytes, max_bytes: int = MAX_HEX_LOG_LENGTH) -> str:
    """
    Safely convert bytes to hex for logging.
    """
    if not isinstance(data, bytes):
        return "<invalid-bytes>"
    
    return data[:max_bytes].hex()


def validate_ip(ip: Optional[str]) -> Tuple[str, bool]:
    """
    Validate IP address format.
    
    Returns:
        Tuple of (ip_string, is_valid)
    """
    if ip is None:
        return "unknown", False
    
    if not isinstance(ip, str):
        return "invalid", False
    
    # Basic IPv4 validation
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    # Basic IPv6 validation (simplified)
    ipv6_pattern = re.compile(r'^[0-9a-fA-F:]+$')
    
    ip = ip[:64]  # Max reasonable IP length
    
    if ipv4_pattern.match(ip):
        # Verify octets are valid
        try:
            octets = [int(x) for x in ip.split('.')]
            if all(0 <= x <= 255 for x in octets):
                return ip, True
        except:
            pass
        return ip, False
    elif ipv6_pattern.match(ip):
        return ip, True
    else:
        # Return sanitized version
        return sanitize_for_log(ip, max_length=64), False


def truncate_for_log(data: bytes, max_bytes: int = MAX_HEX_LOG_LENGTH) -> dict:
    """
    Prepare binary data for logging with metadata.
    """
    if not isinstance(data, bytes):
        return {"error": "not-bytes", "type": str(type(data))}
    
    return {
        "hex": safe_hex(data, max_bytes),
        "length": len(data),
        "truncated": len(data) > max_bytes
    }


# === Protocol-Specific Validators ===

def validate_ssh_fingerprint(fingerprint: Optional[str]) -> str:
    """Validate SSH key fingerprint format."""
    if fingerprint is None:
        return "<null>"
    
    if not isinstance(fingerprint, str):
        return "<invalid>"
    
    # SSH fingerprints are typically SHA256:base64 or MD5:hex
    # Max reasonable length ~128
    return sanitize_for_log(fingerprint, max_length=128)


def validate_ldap_data(data: bytes, max_size: int = 8192) -> Tuple[bytes, bool]:
    """
    Validate LDAP protocol data.
    
    Returns:
        Tuple of (truncated_data, is_within_limits)
    """
    if not isinstance(data, bytes):
        return b"", False
    
    is_valid = len(data) <= max_size
    return data[:max_size], is_valid


def validate_rdp_data(data: bytes, max_size: int = 4096) -> Tuple[bytes, bool]:
    """
    Validate RDP protocol data.
    
    Returns:
        Tuple of (truncated_data, is_within_limits)
    """
    if not isinstance(data, bytes):
        return b"", False
    
    is_valid = len(data) <= max_size
    return data[:max_size], is_valid
