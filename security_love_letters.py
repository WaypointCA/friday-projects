#!/usr/bin/env python3
"""
Security Love Letters Generator
Waypoint Compliance Advisory - waypointca.com

Generate romantic poetry from security logs. Because sometimes
security needs to not take itself so seriously.

Prerequisites:
    None - uses Python standard library only

Usage:
    python security_love_letters.py
    
    Or with your own log file:
    python security_love_letters.py /path/to/auth.log

    Or as a module:
    from security_love_letters import generate_love_letter
    letter = generate_love_letter(log_entries)

Educational Purpose:
    This is mostly for fun, but you'll learn:
    - Common log formats (syslog, auth.log, JSON)
    - Regex parsing of security events
    - Why your SIEM has so much data

GitHub: https://github.com/WaypointCA/friday-projects
"""

import random
import re
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path


# Sample security log entries (if no file provided)
SAMPLE_LOGS = [
    '2026-02-14 03:47:22 Failed password for admin from 192.168.1.42 port 22 ssh2',
    '2026-02-14 08:15:33 Accepted publickey for developer from 10.0.0.15 port 22 ssh2',
    '2026-02-14 09:22:01 Connection closed by 172.16.0.100 port 443 [preauth]',
    '2026-02-14 11:45:17 firewall DENY src=203.0.113.50 dst=10.0.0.5 proto=TCP dport=3389',
    '2026-02-14 14:30:55 User alice logged in from workstation-7',
    '2026-02-14 15:42:08 Possible port scan detected from 198.51.100.23',
    '2026-02-14 16:18:44 Certificate expired for host mail.example.com',
    '2026-02-14 17:05:22 Intrusion detection: SQL injection attempt blocked',
    '2026-02-14 18:33:11 VPN connection established for user bob from 192.0.2.88',
    '2026-02-14 19:47:33 Failed password for root from 10.20.30.40 port 22 ssh2',
    '2026-02-14 20:15:00 Successful 2FA verification for user carol',
    '2026-02-14 21:08:45 Honeypot triggered on port 23 from 45.33.32.156',
    '2026-02-14 22:30:18 Malware signature detected in upload: invoice.pdf.exe',
    '2026-02-14 23:55:02 Rate limit exceeded for API key ending in ...x7k9',
    '2026-02-13 02:14:08 Brute force attack detected: 500 attempts in 60 seconds',
]

# Romantic templates
LOVE_LETTER_TEMPLATES = [
    "Roses are red, violets are blue,\n{event}.",
    "My dearest,\n\nFrom the moment {event},\nI knew we were meant to be.\n\nForever monitoring you.",
    "I'll never forget when we first met—\n{timestamp},\nwhen you first {action}.\n\nYou had me at SYN.",
    "You complete me,\nlike a properly {completion}.",
    "Every time I see {subject},\nmy heart skips a beat.\n\nOr maybe that's just the alerting threshold.",
    "They say love is patient, love is kind.\nBut at {timestamp}, love was\n{event}.",
    "If loving you is wrong,\nI don't want to be {right}.\n\nP.S. {event}",
    "You're the only one who truly {understands} me.\nEven when I {action}.",
    "Our love story:\nFirst connection: {timestamp}\nStatus: {status}\nHeartbeats: ∞",
    "I would traverse every subnet,\nbypass every firewall,\njust to tell you:\n{event}.",
]

# Components for generating romantic interpretations
ROMANTIC_ACTIONS = {
    'failed password': 'knocked on my heart\'s door',
    'accepted': 'opened your heart to me',
    'denied': 'played hard to get',
    'blocked': 'tested my patience (and I loved it)',
    'detected': 'caught my attention',
    'triggered': 'set off fireworks in my soul',
    'connection': 'connected our destinies',
    'expired': 'made me realize time is precious',
    'logged in': 'entered my life',
    'established': 'built something beautiful',
    'exceeded': 'overwhelmed me with feelings',
    'closed': 'left me wanting more',
}

ROMANTIC_SUBJECTS = {
    'firewall': 'your protective nature',
    'port': 'the door to your heart',
    'admin': 'someone who takes charge',
    'root': 'the foundation of us',
    'user': 'the one who completes me',
    'certificate': 'proof of your authenticity',
    'honeypot': 'your irresistible sweetness',
    'vpn': 'our private connection',
    'malware': 'how infectious your smile is',
    'brute force': 'your persistence',
    '2fa': 'double-checking that this is real',
}

COMPLETIONS = [
    'closed vulnerability ticket',
    'terminated TLS handshake',
    'completed three-way handshake',
    'validated authentication token',
    'resolved DNS query',
    'acknowledged TCP segment',
    'encrypted love letter',
    'signed commit message',
]

RIGHTS = [
    'compliant',
    'PCI-DSS certified',
    'in the approved users list',
    'whitelisted',
    'within policy',
]

UNDERSTANDS = [
    'accepts my packets',
    'validates my certificates',
    'trusts my keys',
    'reads my logs',
    'monitors my heartbeat',
]


def parse_log_entry(log: str) -> Dict:
    """
    Extract components from a log entry.
    
    Args:
        log: Raw log line
        
    Returns:
        Dictionary with parsed components
    """
    result = {
        'raw': log,
        'timestamp': None,
        'ip': None,
        'user': None,
        'action': None,
        'port': None,
    }
    
    # Try to extract timestamp
    timestamp_patterns = [
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        r'(\d{2}:\d{2}:\d{2})',
    ]
    for pattern in timestamp_patterns:
        match = re.search(pattern, log)
        if match:
            result['timestamp'] = match.group(1)
            break
    
    # Extract IP addresses
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log)
    if ip_match:
        result['ip'] = ip_match.group(1)
    
    # Extract usernames
    user_match = re.search(r'(?:user|for)\s+(\w+)', log, re.IGNORECASE)
    if user_match:
        result['user'] = user_match.group(1)
    
    # Extract port numbers
    port_match = re.search(r'port\s+(\d+)', log, re.IGNORECASE)
    if port_match:
        result['port'] = port_match.group(1)
    
    # Identify action type
    log_lower = log.lower()
    for keyword in ROMANTIC_ACTIONS.keys():
        if keyword in log_lower:
            result['action'] = keyword
            break
    
    return result


def romanticize_log(parsed: Dict) -> str:
    """
    Convert a parsed log entry into romantic language.
    
    Args:
        parsed: Dictionary from parse_log_entry
        
    Returns:
        Romanticized version of the event
    """
    log_lower = parsed['raw'].lower()
    
    # Build romantic event description
    parts = []
    
    # Add IP reference
    if parsed['ip']:
        parts.append(f"{parsed['ip']} reached out")
    
    # Add action
    if parsed['action'] and parsed['action'] in ROMANTIC_ACTIONS:
        parts.append(ROMANTIC_ACTIONS[parsed['action']])
    
    # Add user reference  
    if parsed['user']:
        parts.append(f"for the love of {parsed['user']}")
    
    # Add port reference
    if parsed['port']:
        parts.append(f"through port {parsed['port']}")
    
    if parts:
        return ', '.join(parts)
    
    # Fallback: use a snippet of the original
    return parsed['raw'][-50:] if len(parsed['raw']) > 50 else parsed['raw']


def generate_love_letter(logs: Optional[List[str]] = None) -> str:
    """
    Generate a romantic love letter from security logs.
    
    Args:
        logs: List of log entries (uses samples if None)
        
    Returns:
        A romantic love letter
    """
    if not logs:
        logs = SAMPLE_LOGS
    
    # Pick a random log and template
    log = random.choice(logs)
    template = random.choice(LOVE_LETTER_TEMPLATES)
    parsed = parse_log_entry(log)
    
    # Build replacement values
    event = romanticize_log(parsed)
    timestamp = parsed['timestamp'] or datetime.now().strftime('%H:%M:%S UTC')
    action = ROMANTIC_ACTIONS.get(parsed['action'], 'entered my life')
    
    # Find a subject from the log
    subject = 'your presence'
    log_lower = log.lower()
    for keyword, romantic in ROMANTIC_SUBJECTS.items():
        if keyword in log_lower:
            subject = romantic
            break
    
    # Generate the letter
    letter = template.format(
        event=event,
        timestamp=timestamp,
        action=action,
        subject=subject,
        completion=random.choice(COMPLETIONS),
        right=random.choice(RIGHTS),
        understands=random.choice(UNDERSTANDS),
        status='Connected 💕',
    )
    
    return letter


def generate_one_liner(logs: Optional[List[str]] = None) -> str:
    """
    Generate a short romantic one-liner from a log.
    
    Args:
        logs: List of log entries (uses samples if None)
        
    Returns:
        A romantic one-liner
    """
    if not logs:
        logs = SAMPLE_LOGS
    
    log = random.choice(logs)
    parsed = parse_log_entry(log)
    
    one_liners = [
        f"Roses are red, violets are blue, {parsed['ip'] or 'someone'} just port scanned you.",
        f"Are you a firewall? Because you've got me feeling blocked... from leaving.",
        f"You must be a SQL injection, because you just dropped my defenses.",
        f"Is your name Wi-Fi? Because I'm feeling a strong connection.",
        f"Are you SSH? Because I want to establish a secure shell with you.",
        f"You had me at SYN.",
        f"My love for you is like {parsed['ip'] or '10.0.0.1'}—private but real.",
        f"You must be TLS 1.3, because you've got perfect forward secrecy.",
        f"I'd never put you on a blocklist.",
        f"You're the ACK to my SYN.",
        f"Our love needs no man-in-the-middle.",
        f"You encrypt my heart with AES-256 feelings.",
    ]
    
    return random.choice(one_liners)


def load_logs_from_file(filepath: str) -> List[str]:
    """
    Load log entries from a file.
    
    Args:
        filepath: Path to log file
        
    Returns:
        List of log entries
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            logs = [line.strip() for line in f if line.strip()]
            return logs if logs else SAMPLE_LOGS
    except Exception as e:
        print(f"Warning: Could not load {filepath}: {e}")
        print("Using sample logs instead.\n")
        return SAMPLE_LOGS


def main():
    """Interactive love letter generator."""
    import sys
    
    print("\n" + "💕" * 25)
    print("\n  SECURITY LOVE LETTERS GENERATOR")
    print("  Happy Valentine's Day from your SIEM")
    print("\n" + "💕" * 25)
    
    # Check for log file argument
    logs = SAMPLE_LOGS
    if len(sys.argv) > 1:
        logs = load_logs_from_file(sys.argv[1])
        print(f"\nLoaded {len(logs)} log entries from {sys.argv[1]}")
    else:
        print("\nUsing sample security logs.")
        print("(Run with a log file path for your own data)")
    
    print("\nCommands: [enter]=new letter, 'one'=one-liner, 'quit'=exit\n")
    
    while True:
        try:
            user_input = input("Press enter for a love letter: ").strip().lower()
            
            if user_input == 'quit':
                print("\n💔 Goodbye! May your logs be clean and your hearts full.\n")
                break
            elif user_input == 'one':
                print("\n" + "-" * 40)
                print(generate_one_liner(logs))
                print("-" * 40 + "\n")
            else:
                print("\n" + "=" * 40)
                print(generate_love_letter(logs))
                print("=" * 40 + "\n")
                
        except KeyboardInterrupt:
            print("\n\n💔 Connection terminated. Until next time.\n")
            break
        except EOFError:
            break


if __name__ == "__main__":
    main()
