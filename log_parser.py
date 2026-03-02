#!/usr/bin/env python3
"""
Auth Log Parser: Brute Force Detector
Waypoint Compliance Advisory - waypointca.com

Parses auth.log and syslog files to detect brute force login attempts.
Groups failed authentication by source IP and flags patterns using
rolling window analysis.

Features:
    - Parses sshd, su, and sudo failure patterns
    - Groups failed attempts by source IP
    - Sliding window brute force detection (configurable threshold and window)
    - Demo mode with realistic synthetic log data
    - ANSI color alerts for brute force flagging

Usage:
    python log_parser.py --demo
    python log_parser.py /var/log/auth.log
    python log_parser.py /var/log/auth.log --threshold 3 --window 600

Educational Purpose:
    Understanding auth log analysis is fundamental to incident detection.
    This tool demonstrates how defenders identify brute force patterns
    and why log monitoring is a critical security control.

GitHub: https://github.com/WaypointCA/friday-projects
"""

import re
import argparse
import random
import collections
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# ANSI color codes for terminal output
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Compiled regex patterns for auth failure detection
# sshd: "Failed password for [invalid user] USERNAME from IP port PORT protocol"
SSHD_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)"
)

# su: "FAILED su for TARGET by USER"
SU_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+su\[\d+\]:\s+"
    r"FAILED su for (\S+) by (\S+)"
)

# sudo: "USER : N incorrect password attempt"
SUDO_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sudo\[\d+\]:\s+"
    r"(\S+)\s+:\s+\d+\s+incorrect password attempt"
)

# Demo data pools using RFC 5737/6890 documentation and private ranges
DEMO_IPS = [
    "198.51.100.47",   # RFC 5737 TEST-NET-2: will be brute forcer
    "203.0.113.88",    # RFC 5737 TEST-NET-3: spread-out failures
    "192.0.2.15",      # RFC 5737 TEST-NET-1: light noise
    "10.0.0.201",      # RFC 1918 private: light noise
    "172.16.44.9",     # RFC 1918 private: light noise
]
DEMO_USERS = ["root", "admin", "ubuntu", "deploy", "postgres", "www-data", "jenkins"]
DEMO_HOSTNAME = "webserver01"

# Default detection parameters
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = 600  # seconds (10 minutes)


def parse_log_line(line: str) -> Optional[Tuple[str, str, str, str]]:
    """Parse a single log line for failed authentication events.

    Attempts each regex pattern in order: sshd, su, sudo.

    Args:
        line: Raw log line string.

    Returns:
        Tuple of (timestamp, username, ip, service) or None if no match.
    """
    match = SSHD_PATTERN.search(line)
    if match:
        return (match.group(1), match.group(2), match.group(3), "sshd")
    match = SU_PATTERN.search(line)
    if match:
        # su logs target user; source IP not available, use "local"
        return (match.group(1), match.group(2), "local", "su")
    match = SUDO_PATTERN.search(line)
    if match:
        return (match.group(1), match.group(2), "local", "sudo")
    return None


def parse_log(lines: List[str]) -> Dict[str, List[dict]]:
    """Parse multiple log lines and group failed attempts by source IP.

    Args:
        lines: List of raw log line strings.

    Returns:
        Dict mapping IP to list of attempt dicts with keys:
        timestamp, username, service, raw_timestamp.
    """
    attempts: Dict[str, List[dict]] = collections.defaultdict(list)
    year = datetime.now().year

    for line in lines:
        result = parse_log_line(line)
        if result is None:
            continue
        ts_str, username, ip, service = result
        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            # Handle Dec/Jan rollover: if parsed date is in the future by
            # more than a day, assume it belongs to the previous year
            if dt > datetime.now() + timedelta(days=1):
                dt = dt.replace(year=year - 1)
        except ValueError:
            continue
        attempts[ip].append({
            "timestamp": dt,
            "username": username,
            "service": service,
            "raw_timestamp": ts_str,
        })

    return dict(attempts)


def detect_brute_force(
    attempts: Dict[str, List[dict]],
    threshold: int = DEFAULT_THRESHOLD,
    window: int = DEFAULT_WINDOW,
) -> List[Tuple[str, int]]:
    """Detect brute force patterns using a sliding window algorithm.

    For each IP, sorts attempts by timestamp and uses two pointers to find
    the maximum number of attempts within any window of the given size.

    Args:
        attempts: Dict mapping IP to list of attempt dicts.
        threshold: Minimum failures in a window to flag as brute force.
        window: Window size in seconds.

    Returns:
        List of (ip, max_count) tuples for flagged IPs, sorted by count descending.
    """
    alerts: List[Tuple[str, int]] = []

    for ip, events in attempts.items():
        sorted_events = sorted(events, key=lambda e: e["timestamp"])
        timestamps = [e["timestamp"] for e in sorted_events]
        max_count = 0
        left = 0

        for right in range(len(timestamps)):
            # Advance left pointer while window is exceeded
            while (timestamps[right] - timestamps[left]).total_seconds() > window:
                left += 1
            count = right - left + 1
            if count > max_count:
                max_count = count

        if max_count >= threshold:
            alerts.append((ip, max_count))

    return sorted(alerts, key=lambda a: a[1], reverse=True)


def generate_demo_log() -> List[str]:
    """Generate realistic demo auth log entries and write to /tmp/demo_auth.log.

    Creates a mix of sshd, su, and sudo failures across five IPs:
    - IP[0]: 8-10 failures clustered in 30 minutes (triggers brute force)
    - IP[1]: 6 failures spread over 3 hours (below default window threshold)
    - IP[2-4]: 1-2 failures each (normal background noise)

    Returns:
        List of generated log lines.
    """
    lines: List[str] = []
    base_time = datetime.now().replace(second=0, microsecond=0) - timedelta(hours=4)

    # IP[0]: concentrated brute force burst (8-10 attempts in ~8 min)
    burst_count = random.randint(8, 10)
    for i in range(burst_count):
        t = base_time + timedelta(seconds=random.randint(0, 480))
        ts = t.strftime("%b %d %H:%M:%S")
        user = random.choice(DEMO_USERS)
        lines.append(
            f"{ts} {DEMO_HOSTNAME} sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for invalid user {user} from {DEMO_IPS[0]} port "
            f"{random.randint(40000, 60000)} ssh2"
        )

    # IP[1]: spread out over 3 hours (6 attempts)
    for i in range(6):
        t = base_time + timedelta(minutes=i * 35 + random.randint(0, 10))
        ts = t.strftime("%b %d %H:%M:%S")
        user = random.choice(DEMO_USERS)
        lines.append(
            f"{ts} {DEMO_HOSTNAME} sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for {user} from {DEMO_IPS[1]} port "
            f"{random.randint(40000, 60000)} ssh2"
        )

    # IP[2]: one su failure
    t = base_time + timedelta(minutes=random.randint(60, 120))
    ts = t.strftime("%b %d %H:%M:%S")
    lines.append(
        f"{ts} {DEMO_HOSTNAME} su[{random.randint(1000, 9999)}]: "
        f"FAILED su for root by {random.choice(DEMO_USERS)}"
    )

    # IP[3]: one sudo failure
    t = base_time + timedelta(minutes=random.randint(90, 150))
    ts = t.strftime("%b %d %H:%M:%S")
    user = random.choice(DEMO_USERS)
    lines.append(
        f"{ts} {DEMO_HOSTNAME} sudo[{random.randint(1000, 9999)}]: "
        f"{user} : 3 incorrect password attempts"
    )

    # IP[4]: two sshd failures
    for _ in range(2):
        t = base_time + timedelta(minutes=random.randint(30, 180))
        ts = t.strftime("%b %d %H:%M:%S")
        user = random.choice(DEMO_USERS)
        lines.append(
            f"{ts} {DEMO_HOSTNAME} sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for {user} from {DEMO_IPS[4]} port "
            f"{random.randint(40000, 60000)} ssh2"
        )

    # Sort by timestamp string for realistic log ordering
    lines.sort()

    # Write to /tmp for user inspection
    demo_path = "/tmp/demo_auth.log"
    with open(demo_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Demo log written to {demo_path}")

    return lines


def format_report(
    attempts: Dict[str, List[dict]],
    alerts: List[Tuple[str, int]],
    threshold: int,
    window: int,
) -> None:
    """Print a formatted report of parsed attempts and brute force alerts.

    Args:
        attempts: Dict mapping IP to list of attempt dicts.
        alerts: List of (ip, max_count) tuples for flagged IPs.
        threshold: Threshold used for detection.
        window: Window size in seconds used for detection.
    """
    print("\n" + "=" * 50)
    print("AUTH LOG PARSER: BRUTE FORCE DETECTOR")
    print("Waypoint Compliance Advisory")
    print("=" * 50)

    total_attempts = sum(len(v) for v in attempts.values())
    print(f"\nTotal failed attempts: {total_attempts}")
    print(f"Unique source IPs: {len(attempts)}")
    print(f"Detection window: {window}s | Threshold: {threshold} failures")

    print("\n" + "-" * 50)
    print("FAILED ATTEMPTS BY SOURCE IP")
    print("-" * 50)

    alert_ips = {ip for ip, _ in alerts}
    for ip in sorted(attempts.keys(), key=lambda k: len(attempts[k]), reverse=True):
        events = attempts[ip]
        flag = f"  {RED}{BOLD}[BRUTE FORCE]{RESET}" if ip in alert_ips else ""
        print(f"\n  {ip}: {len(events)} attempts{flag}")
        # Show up to 3 sample entries
        for event in events[:3]:
            print(
                f"    {event['raw_timestamp']}  {event['service']:<6} "
                f"user={event['username']}"
            )
        if len(events) > 3:
            print(f"    ... and {len(events) - 3} more")

    if alerts:
        print("\n" + "-" * 50)
        print(f"{RED}{BOLD}BRUTE FORCE ALERTS{RESET}")
        print("-" * 50)
        for ip, count in alerts:
            print(f"  {RED}{BOLD}{ip}{RESET}: {count} failures within {window}s window")
    else:
        print("\n" + "-" * 50)
        print("No brute force patterns detected.")
        print("-" * 50)

    print("\n" + "=" * 50 + "\n")


def main() -> None:
    """Entry point: parse arguments, run analysis, print report."""
    parser = argparse.ArgumentParser(
        description="Auth Log Parser: detect brute force login attempts.",
        epilog="Example: python log_parser.py /var/log/auth.log --threshold 5",
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Path to auth.log or syslog file to parse.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate and parse synthetic demo log data.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Failures in window to flag as brute force (default: {DEFAULT_THRESHOLD}).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW,
        help=f"Detection window in seconds (default: {DEFAULT_WINDOW}).",
    )
    args = parser.parse_args()

    # Validate parameters
    if args.threshold < 1:
        print("Error: threshold must be a positive integer.")
        raise SystemExit(1)
    if args.window < 1:
        print("Error: window must be a positive integer.")
        raise SystemExit(1)

    # Determine input source
    if args.demo:
        lines = generate_demo_log()
    elif args.logfile:
        try:
            with open(args.logfile, "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"Error: file not found: {args.logfile}")
            raise SystemExit(1)
        except PermissionError:
            print(f"Error: permission denied: {args.logfile}")
            raise SystemExit(1)
    else:
        parser.print_help()
        raise SystemExit(0)

    # Parse and analyze
    attempts = parse_log(lines)

    if not attempts:
        print("No failed authentication attempts found in input.")
        raise SystemExit(0)

    alerts = detect_brute_force(attempts, args.threshold, args.window)
    format_report(attempts, alerts, args.threshold, args.window)


if __name__ == "__main__":
    main()
