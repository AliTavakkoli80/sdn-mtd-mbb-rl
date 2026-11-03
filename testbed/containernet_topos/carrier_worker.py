#!/usr/bin/env python3
"""
carrier_worker.py - Background carrier traffic generator inside containernet hosts (mn.h3, mn.h4).
Periodically queries DNS (10.0.0.254) for the target hostname (e.g. host7.com) to obtain the active VIP,
and runs controlled 3-second TCP transfers via iperf3.
This faithfully simulates authentic client sessions migrating to updated VIPs while allowing
retired Table 1 grace sessions to genuinely become idle and expire after 15 seconds in OVS.
"""

import sys
import os
import time
import subprocess
import re
import argparse


def resolve_domain(domain, dns_ip="10.0.0.254"):
    try:
        cmd = f"nslookup {domain} {dns_ip}"
        res = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.0
        )
        ips = re.findall(r'\b10\.0\.0\.\d+\b', res.stdout)
        valid = [ip for ip in ips if ip != dns_ip]
        if valid:
            return valid[-1]
    except Exception:
        pass
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Target domain, e.g. host7.com")
    parser.add_argument('--port', type=int, default=5201, help="Target port")
    parser.add_argument('--bandwidth', default="10M", help="Bandwidth")
    parser.add_argument('--burst', type=int, default=3, help="Duration of each burst in seconds")
    parser.add_argument('--pause', type=float, default=0.5, help="Pause between bursts")
    parser.add_argument('--dns', default="10.0.0.254", help="DNS server IP")
    args = parser.parse_args()

    while True:
        vip = resolve_domain(args.target, args.dns)
        if not vip:
            time.sleep(1.0)
            continue

        cmd = f"iperf3 -c {vip} -p {args.port} -t {args.burst} -b {args.bandwidth} >/dev/null 2>&1"
        subprocess.run(cmd, shell=True)
        time.sleep(args.pause)


if __name__ == '__main__':
    main()
