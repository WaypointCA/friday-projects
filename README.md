# Friday Security Projects

Small, educational security projects for learning Python and security concepts.

**Waypoint Compliance Advisory** - [waypointca.com](https://waypointca.com)

---

## Projects

### 1. Password Strength Checker
**File:** `password_strength_checker.py`

A password strength checker that goes beyond "has uppercase." Most password meters are security theater—this one actually checks what matters.

**Features:**
- Entropy calculation (not just character type counting)
- Common password list checking (embedded top 100 + optional SecLists)
- Keyboard pattern detection (qwerty, 12345, etc.)
- L33t speak substitution detection
- Have I Been Pwned check via k-anonymity (password never leaves your machine)

**Usage:**
```bash
python password_strength_checker.py
```

**What you'll learn:**
- Why "P@ssw0rd!" is terrible despite passing most checkers
- How entropy actually measures password strength
- How HIBP's k-anonymity API protects your password while checking breaches
- Why character substitutions don't add real security

---

### 2. Security Love Letters
**File:** `security_love_letters.py`

Generate romantic poetry from security logs. Because sometimes security needs to not take itself so seriously.

**Features:**
- Parses common log formats (syslog, auth.log)
- Multiple romantic letter templates
- One-liner security puns
- Works with your own log files

**Usage:**
```bash
python security_love_letters.py
python security_love_letters.py /var/log/auth.log
```

**Sample output:**
```
Roses are red, violets are blue,
192.168.1.42 reached out, knocked on my heart's door.

---

You had me at SYN.
```

**What you'll learn:**
- Common security log formats
- Regex parsing of security events
- Why your SIEM has so much data (and how to have fun with it)

---

### 3. Port Scanner
**File:** `port_scanner.py`

A basic port scanner in under 50 lines of core logic. The goal isn't to replace nmap—it's to understand what's actually happening when you scan.

**Features:**
- TCP connect scanning
- Multi-threaded (50 concurrent connections)
- Service name detection
- Common port list built-in
- Custom port range support

**Usage:**
```bash
python port_scanner.py scanme.nmap.org
python port_scanner.py 192.168.1.1 1 1024
python port_scanner.py localhost --common
```

**Sample output:**
```
Target: scanme.nmap.org (45.33.32.156)
Scanning: 17 common ports

PORT       STATE      SERVICE
22         open       ssh
80         open       http

Scanned 17 ports in 1.24 seconds
```

**What you'll learn:**
- How TCP connect scanning works (full three-way handshake)
- Why this scan is "noisy" (shows up in logs)
- What SYN scans do differently (and why they need raw sockets)
- How threading speeds up network operations

---

### 4. Hash Cracker
**File:** `hash_cracker.py`

A wordlist-based hash cracker demonstrating why weak passwords fail fast.

**Features:**
- Supports MD5, SHA1, SHA256 (auto-detected)
- Built-in common password list
- Works with custom wordlists (rockyou.txt, SecLists)
- Shows crack rate and brute force time estimates
- Test mode to generate hashes for any password

**Usage:**
```bash
python hash_cracker.py 482c811da5d5b4bc6d497ffa98491e38
python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt
python hash_cracker.py --test mysecretpassword
```

**Sample output:**
```
✅ CRACKED!
   Password:  password123
   Attempts:  25
   Time:      0.0001 seconds

BRUTE FORCE TIME ESTIMATES (at 1M hashes/sec):
  6 lowercase letters:     5.1 minutes
  8 lowercase letters:     2.4 days
  8 mixed case + numbers:  6.9 years
  12 mixed + symbols:      1.51e+10 years
```

**What you'll learn:**
- Why weak passwords crack in milliseconds
- Why strong passwords take years (or longer)
- The math behind password complexity
- How wordlist attacks differ from brute force

---

## Requirements

All projects use **Python 3.8+** and **standard library only** (no pip install needed).

Optional enhancements may suggest external resources like SecLists or rockyou.txt.

---

## Responsible Use

These tools are for **education only**. 

- Only scan systems you own or have explicit permission to test
- Only crack hashes you're authorized to test
- Understand your local laws regarding security testing

---

## License

MIT License - Use freely, learn something, build something better.

---

## About

These projects accompany my LinkedIn posts on practical security topics. The goal is education—understanding how things work makes you better at defending against them.

**Cameron Hopkin**  
Security Engineering Manager | CISSP, CEH, CHFI  
[LinkedIn](https://www.linkedin.com/in/cameronhopkin/) | [Waypoint Compliance Advisory](https://waypointca.com)
