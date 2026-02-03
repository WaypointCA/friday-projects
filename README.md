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

## Coming Soon

- **Security Love Letters** - Generate romantic poetry from SIEM logs
- **Port Scanner** - Build a basic scanner in 50 lines (understand what nmap does)
- **Hash Cracker** - Wordlist attack demo (understand why weak passwords fail)

---

## Requirements

All projects use Python 3.8+ and standard library only (no pip install needed).

Optional enhancements may suggest external resources like SecLists.

---

## License

MIT License - Use freely, learn something, build something better.

---

## About

These projects accompany my LinkedIn posts on practical security topics. The goal is education—understanding how things work makes you better at defending against them.

Follow along: [LinkedIn](https://www.linkedin.com/in/cameronhopkin/)
