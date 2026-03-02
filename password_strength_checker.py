#!/usr/bin/env python3
"""
Password Strength Checker
Waypoint Compliance Advisory - waypointca.com

A password strength checker that goes beyond "has uppercase."

Features:
    - Checks against common password lists
    - Detects keyboard patterns (qwerty, 12345)
    - Calculates actual entropy
    - Checks Have I Been Pwned via k-anonymity (no password sent)

Prerequisites:
    None - uses Python standard library only
    
    Optional: Download SecLists for expanded password checking:
    https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt

Usage:
    python password_strength_checker.py
    
    Or as a module:
    from password_strength_checker import check_password_strength
    result = check_password_strength("mypassword")

Educational Purpose:
    This demonstrates why most "password strength meters" are theater.
    A password like "P@ssw0rd!" passes most checkers but is terrible.
    Real strength comes from entropy and avoiding known patterns.

GitHub: https://github.com/WaypointCA/friday-projects
"""

import hashlib
import math
import re
import string
import urllib.request
import ssl
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# Common keyboard patterns to check
KEYBOARD_PATTERNS = [
    # Horizontal rows
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwerty", "asdfgh", "zxcvbn",
    "qwert", "asdfg", "zxcvb",
    # Number sequences
    "1234567890", "123456789", "12345678", "1234567", "123456", "12345", "1234",
    "0987654321", "987654321", "87654321", "7654321", "654321", "54321", "4321",
    # Common patterns
    "abcdefgh", "abcdef", "abcd",
    "password", "passw0rd", "p@ssword", "p@ssw0rd",
    "letmein", "welcome", "admin", "login",
    "qazwsx", "1qaz2wsx", "1q2w3e4r",
]

# Character set sizes for entropy calculation
CHARSET_SIZES = {
    'lowercase': 26,
    'uppercase': 26,
    'digits': 10,
    'special': 32,  # Common special characters
}


def load_common_passwords(filepath: Optional[str] = None) -> set:
    """
    Load common passwords from a file or use embedded top 100.
    
    For full checking, download SecLists:
    https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
    
    Args:
        filepath: Path to password list file (one password per line)
        
    Returns:
        Set of common passwords (lowercase for comparison)
    """
    # Embedded top 100 most common passwords
    # Source: Various breach analyses
    TOP_100 = {
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "shadow", "master", "666666", "qwertyuiop",
        "123321", "mustang", "1234567890", "michael", "654321",
        "superman", "1qaz2wsx", "7777777", "121212", "000000",
        "qazwsx", "123qwe", "killer", "trustno1", "jordan",
        "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
        "soccer", "harley", "batman", "andrew", "tigger",
        "sunshine", "iloveyou", "2000", "charlie", "robert",
        "thomas", "hockey", "ranger", "daniel", "starwars",
        "klaster", "112233", "george", "computer", "michelle",
        "jessica", "pepper", "1111", "zxcvbn", "555555",
        "11111111", "131313", "freedom", "777777", "pass",
        "maggie", "159753", "aaaaaa", "ginger", "princess",
        "joshua", "cheese", "amanda", "summer", "love",
        "ashley", "nicole", "chelsea", "biteme", "matthew",
        "access", "yankees", "987654321", "dallas", "austin",
        "thunder", "taylor", "matrix", "mobilemail", "mom",
        "monitor", "monitoring", "montana", "moon", "moscow",
    }
    
    if filepath and Path(filepath).exists():
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                external = {line.strip().lower() for line in f if line.strip()}
                return TOP_100.union(external)
        except Exception as e:
            print(f"Warning: Could not load {filepath}: {e}")
    
    return TOP_100


def calculate_entropy(password: str) -> float:
    """
    Calculate the entropy of a password in bits.
    
    Entropy = length * log2(charset_size)
    
    Higher entropy = harder to brute force.
    - < 28 bits: Very weak (can be cracked instantly)
    - 28-35 bits: Weak (crackable in minutes to hours)
    - 36-59 bits: Reasonable (crackable in days to years)
    - 60-127 bits: Strong (crackable in years to centuries)
    - 128+ bits: Very strong
    
    Args:
        password: The password to analyze
        
    Returns:
        Entropy in bits
    """
    if not password:
        return 0.0
    
    charset_size = 0
    
    if any(c in string.ascii_lowercase for c in password):
        charset_size += CHARSET_SIZES['lowercase']
    if any(c in string.ascii_uppercase for c in password):
        charset_size += CHARSET_SIZES['uppercase']
    if any(c in string.digits for c in password):
        charset_size += CHARSET_SIZES['digits']
    if any(c in string.punctuation for c in password):
        charset_size += CHARSET_SIZES['special']
    
    if charset_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


def check_keyboard_patterns(password: str) -> List[str]:
    """
    Check for common keyboard patterns in the password.
    
    Args:
        password: The password to check
        
    Returns:
        List of detected patterns
    """
    found_patterns = []
    password_lower = password.lower()
    
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            found_patterns.append(pattern)
        # Also check reversed patterns
        if pattern[::-1] in password_lower:
            found_patterns.append(f"{pattern[::-1]} (reversed)")
    
    return found_patterns


def check_character_substitutions(password: str) -> bool:
    """
    Check if password uses common l33t speak substitutions.
    
    These don't add real security because attackers know them.
    
    Args:
        password: The password to check
        
    Returns:
        True if substitutions detected
    """
    # Common substitutions
    substitutions = {
        '@': 'a', '4': 'a',
        '3': 'e',
        '1': 'i', '!': 'i',
        '0': 'o',
        '$': 's', '5': 's',
        '7': 't',
    }
    
    # Convert back to letters
    normalized = password.lower()
    for sub, letter in substitutions.items():
        normalized = normalized.replace(sub, letter)
    
    # Check if normalized version is in common passwords
    common = load_common_passwords()
    return normalized in common


def check_hibp(password: str) -> Tuple[bool, int]:
    """
    Check if password appears in Have I Been Pwned database.
    
    Uses k-anonymity: only sends first 5 characters of SHA-1 hash.
    The full password never leaves your machine.
    
    Args:
        password: The password to check
        
    Returns:
        Tuple of (found_in_breach, breach_count)
    """
    # SHA-1 hash the password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        # Create SSL context that doesn't verify (for simplicity)
        # In production, you'd want proper cert verification
        ctx = ssl.create_default_context()
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={'User-Agent': 'PasswordStrengthChecker'})
        
        with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
            hash_list = response.read().decode('utf-8')
        
        # Check if our suffix is in the returned list
        for line in hash_list.splitlines():
            parts = line.split(':')
            if len(parts) == 2:
                hash_suffix, count = parts
                if hash_suffix == suffix:
                    return True, int(count)
        
        return False, 0
        
    except Exception as e:
        # Network error - can't check HIBP
        return False, -1  # -1 indicates check failed


def check_password_strength(password: str, wordlist_path: Optional[str] = None) -> Dict:
    """
    Comprehensive password strength check.
    
    Args:
        password: The password to analyze
        wordlist_path: Optional path to common passwords file
        
    Returns:
        Dictionary with strength analysis results
    """
    results = {
        'password_length': len(password),
        'entropy_bits': 0.0,
        'entropy_rating': '',
        'in_common_list': False,
        'keyboard_patterns': [],
        'uses_substitutions': False,
        'hibp_found': False,
        'hibp_count': 0,
        'issues': [],
        'score': 0,  # 0-100
        'rating': '',
    }
    
    if not password:
        results['issues'].append("Password is empty")
        results['rating'] = "Invalid"
        return results
    
    # Length check
    if len(password) < 8:
        results['issues'].append("Password is too short (minimum 8 characters)")
    elif len(password) < 12:
        results['issues'].append("Password is short (12+ characters recommended)")
    
    # Entropy calculation
    entropy = calculate_entropy(password)
    results['entropy_bits'] = entropy
    
    if entropy < 28:
        results['entropy_rating'] = "Very Weak"
    elif entropy < 36:
        results['entropy_rating'] = "Weak"
    elif entropy < 60:
        results['entropy_rating'] = "Reasonable"
    elif entropy < 128:
        results['entropy_rating'] = "Strong"
    else:
        results['entropy_rating'] = "Very Strong"
    
    # Common password check
    common_passwords = load_common_passwords(wordlist_path)
    if password.lower() in common_passwords:
        results['in_common_list'] = True
        results['issues'].append("Password is in common password list")
    
    # Keyboard pattern check
    patterns = check_keyboard_patterns(password)
    if patterns:
        results['keyboard_patterns'] = patterns
        results['issues'].append(f"Contains keyboard patterns: {', '.join(patterns[:3])}")
    
    # Substitution check
    if check_character_substitutions(password):
        results['uses_substitutions'] = True
        results['issues'].append("Uses common character substitutions (e.g., @ for a)")
    
    # HIBP check
    hibp_found, hibp_count = check_hibp(password)
    results['hibp_found'] = hibp_found
    results['hibp_count'] = hibp_count
    
    if hibp_count == -1:
        results['issues'].append("Could not check breach database (network error)")
    elif hibp_found:
        results['issues'].append(f"Found in {hibp_count:,} data breaches!")
    
    # Calculate overall score
    score = 100
    
    # Length penalties/bonuses
    if len(password) < 8:
        score -= 40
    elif len(password) < 12:
        score -= 15
    elif len(password) >= 16:
        score += 10
    
    # Entropy-based scoring
    if entropy < 28:
        score -= 30
    elif entropy < 36:
        score -= 20
    elif entropy < 60:
        score -= 5
    elif entropy >= 80:
        score += 10
    
    # Penalty for common password
    if results['in_common_list']:
        score -= 50
    
    # Penalty for keyboard patterns
    score -= len(results['keyboard_patterns']) * 10
    
    # Penalty for substitutions that don't help
    if results['uses_substitutions']:
        score -= 10
    
    # Major penalty for breached passwords
    if results['hibp_found']:
        score -= 40
    
    # Clamp score
    score = max(0, min(100, score))
    results['score'] = score
    
    # Overall rating
    if score >= 80:
        results['rating'] = "Strong"
    elif score >= 60:
        results['rating'] = "Moderate"
    elif score >= 40:
        results['rating'] = "Weak"
    else:
        results['rating'] = "Very Weak"
    
    return results


def print_results(results: Dict) -> None:
    """Pretty print the password analysis results."""
    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH ANALYSIS")
    print("=" * 50)
    
    print(f"\nLength: {results['password_length']} characters")
    print(f"Entropy: {results['entropy_bits']} bits ({results['entropy_rating']})")
    
    print(f"\nChecks:")
    print(f"  Common password list: {'❌ FOUND' if results['in_common_list'] else '✓ Not found'}")
    print(f"  Keyboard patterns: {'❌ ' + ', '.join(results['keyboard_patterns'][:2]) if results['keyboard_patterns'] else '✓ None detected'}")
    leet_msg = "⚠️  Detected (does not add security)" if results['uses_substitutions'] else "✓ None"
    print(f"  L33t substitutions: {leet_msg}")
    
    if results['hibp_count'] == -1:
        print(f"  Breach database: ⚠️  Could not check (network error)")
    elif results['hibp_found']:
        print(f"  Breach database: ❌ Found in {results['hibp_count']:,} breaches!")
    else:
        print(f"  Breach database: ✓ Not found in known breaches")
    
    print(f"\nOverall Score: {results['score']}/100")
    
    rating_emoji = {
        'Strong': '✅',
        'Moderate': '⚠️',
        'Weak': '❌',
        'Very Weak': '🚫',
        'Invalid': '❓',
    }
    print(f"Rating: {rating_emoji.get(results['rating'], '?')} {results['rating']}")
    
    if results['issues']:
        print(f"\nIssues Found:")
        for issue in results['issues']:
            print(f"  • {issue}")
    
    print("\n" + "=" * 50)


def interactive_mode() -> None:
    """Run interactive password checker."""
    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH CHECKER")
    print("Waypoint Compliance Advisory")
    print("=" * 50)
    print("\nThis tool checks password strength using:")
    print("  • Entropy calculation")
    print("  • Common password lists")
    print("  • Keyboard pattern detection")
    print("  • Have I Been Pwned database (k-anonymity)")
    print("\nYour password is never stored or transmitted.")
    print("(HIBP check only sends first 5 chars of hash)")
    print("\nType 'quit' to exit.\n")
    
    while True:
        try:
            password = input("Enter password to check: ")
            
            if password.lower() == 'quit':
                print("\nGoodbye!")
                break
            
            if not password:
                print("Please enter a password.\n")
                continue
            
            results = check_password_strength(password)
            print_results(results)
            print()
            
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except EOFError:
            break


if __name__ == "__main__":
    interactive_mode()
