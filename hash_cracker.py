#!/usr/bin/env python3
"""
Simple Hash Cracker
Waypoint Compliance Advisory - waypointca.com

A wordlist-based hash cracker to demonstrate why weak passwords fail.

Prerequisites:
    None - uses Python standard library only
    
    Optional: Download rockyou.txt or other wordlists:
    https://github.com/danielmiessler/SecLists/tree/master/Passwords

Usage:
    python hash_cracker.py <hash> [wordlist]
    python hash_cracker.py <hash> --generate  # Use built-in common passwords
    
    Examples:
    python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt
    python hash_cracker.py 482c811da5d5b4bc6d497ffa98491e38 --generate

Educational Purpose:
    This demonstrates:
    - Why weak passwords are cracked in seconds
    - Why strong passwords take years (or longer)
    - How salting defeats precomputed attacks
    - The relationship between password complexity and crack time

GitHub: https://github.com/WaypointCA/friday-projects
"""

import hashlib
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

# Built-in common passwords for demo
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123",
    "batman", "login", "admin", "welcome", "hello",
    "charlie", "donald", "password1!", "qwerty123", "admin123",
]


def hash_password(password: str, algorithm: str = "md5") -> str:
    """
    Hash a password using the specified algorithm.
    
    Args:
        password: Plain text password
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hexadecimal hash string
    """
    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def detect_hash_type(hash_str: str) -> str:
    """
    Detect hash type based on length.
    
    Args:
        hash_str: The hash to analyze
        
    Returns:
        Detected algorithm name
    """
    length = len(hash_str)
    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    else:
        return "unknown"


def crack_hash(target_hash: str, wordlist_path: Optional[str] = None, 
               algorithm: Optional[str] = None) -> Tuple[Optional[str], int, float]:
    """
    Attempt to crack a hash using a wordlist.
    
    Args:
        target_hash: The hash to crack
        wordlist_path: Path to wordlist file (None for built-in list)
        algorithm: Hash algorithm (auto-detected if None)
        
    Returns:
        Tuple of (cracked_password or None, attempts, elapsed_time)
    """
    target_hash = target_hash.lower().strip()
    
    # Auto-detect algorithm
    if algorithm is None:
        algorithm = detect_hash_type(target_hash)
        if algorithm == "unknown":
            print(f"Warning: Unknown hash length ({len(target_hash)}), assuming MD5")
            algorithm = "md5"
    
    attempts = 0
    start_time = time.time()
    
    # Load wordlist
    if wordlist_path and Path(wordlist_path).exists():
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = (line.strip() for line in f if line.strip())
                
                for password in passwords:
                    attempts += 1
                    if hash_password(password, algorithm) == target_hash:
                        elapsed = time.time() - start_time
                        return (password, attempts, elapsed)
                    
                    # Progress indicator every 100k attempts
                    if attempts % 100000 == 0:
                        print(f"  Tried {attempts:,} passwords...", end='\r')
                        
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return (None, attempts, time.time() - start_time)
    else:
        # Use built-in list
        for password in COMMON_PASSWORDS:
            attempts += 1
            if hash_password(password, algorithm) == target_hash:
                elapsed = time.time() - start_time
                return (password, attempts, elapsed)
    
    elapsed = time.time() - start_time
    return (None, attempts, elapsed)


def generate_test_hash(password: str = "password123") -> None:
    """Generate test hashes for a password."""
    print(f"\nTest hashes for '{password}':")
    print(f"  MD5:    {hash_password(password, 'md5')}")
    print(f"  SHA1:   {hash_password(password, 'sha1')}")
    print(f"  SHA256: {hash_password(password, 'sha256')}")


def estimate_crack_time(charset_size: int, length: int, rate: float = 1000000) -> str:
    """
    Estimate time to brute force a password.
    
    Args:
        charset_size: Number of possible characters
        length: Password length
        rate: Hashes per second (default 1M/sec for fast hash)
        
    Returns:
        Human readable time estimate
    """
    combinations = charset_size ** length
    seconds = combinations / rate
    
    if seconds < 1:
        return "instant"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 31536000 * 100:
        return f"{seconds/31536000:.1f} years"
    else:
        return f"{seconds/31536000:.2e} years"


def main() -> None:
    """Main entry point."""
    print("\n" + "=" * 55)
    print("SIMPLE HASH CRACKER")
    print("Educational demonstration - use responsibly")
    print("=" * 55)
    
    if len(sys.argv) < 2:
        print(f"\nUsage: {sys.argv[0]} <hash> [wordlist]")
        print(f"       {sys.argv[0]} <hash> --generate")
        print(f"       {sys.argv[0]} --test [password]")
        print("\nExamples:")
        print("  python hash_cracker.py 482c811da5d5b4bc6d497ffa98491e38")
        print("  python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt")
        print("  python hash_cracker.py --test mysecretpassword")
        print("\nSupported hash types: MD5 (32 char), SHA1 (40 char), SHA256 (64 char)")
        sys.exit(1)
    
    # Test mode - generate hashes for a password
    if sys.argv[1] == "--test":
        password = sys.argv[2] if len(sys.argv) > 2 else "password123"
        generate_test_hash(password)
        sys.exit(0)
    
    target_hash = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Detect hash type
    hash_type = detect_hash_type(target_hash)
    
    print(f"\nTarget hash: {target_hash}")
    print(f"Hash type:   {hash_type.upper()} (detected by length)")
    
    if wordlist and wordlist != "--generate":
        if Path(wordlist).exists():
            # Count lines for estimate
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                word_count = sum(1 for _ in f)
            print(f"Wordlist:    {wordlist} ({word_count:,} words)")
        else:
            print(f"Wordlist:    {wordlist} (file not found, using built-in)")
            wordlist = None
    else:
        print(f"Wordlist:    Built-in ({len(COMMON_PASSWORDS)} common passwords)")
        wordlist = None
    
    print("-" * 55)
    print("Cracking...\n")
    
    # Attempt to crack
    password, attempts, elapsed = crack_hash(target_hash, wordlist, hash_type)
    
    print(" " * 50)  # Clear progress line
    print("-" * 55)
    
    if password:
        print(f"\n✅ CRACKED!")
        print(f"   Password:  {password}")
        print(f"   Attempts:  {attempts:,}")
        print(f"   Time:      {elapsed:.4f} seconds")
        print(f"   Rate:      {attempts/elapsed:,.0f} hashes/sec" if elapsed > 0 else "")
    else:
        print(f"\n❌ NOT FOUND in wordlist")
        print(f"   Attempts:  {attempts:,}")
        print(f"   Time:      {elapsed:.4f} seconds")
    
    # Educational comparison
    print("\n" + "-" * 55)
    print("BRUTE FORCE TIME ESTIMATES (at 1M hashes/sec):")
    print("-" * 55)
    print(f"  6 lowercase letters:     {estimate_crack_time(26, 6)}")
    print(f"  8 lowercase letters:     {estimate_crack_time(26, 8)}")
    print(f"  8 mixed case + numbers:  {estimate_crack_time(62, 8)}")
    print(f"  12 mixed + symbols:      {estimate_crack_time(94, 12)}")
    print(f"  16 mixed + symbols:      {estimate_crack_time(94, 16)}")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
