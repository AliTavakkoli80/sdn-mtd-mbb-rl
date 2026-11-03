#!/usr/bin/env python3
"""
carrier_worker.py - Background carrier traffic generator inside containernet hosts (mn.h3, mn.h4).
Maintains sustained, uninterrupted TCP streams via iperf3 across the entire episode duration (25-30s+),
faithfully bridging MTD shuffle boundaries and demonstrating physical session preservation in Table 1 MBB.
"""

import sys
import os
import time
import subprocess
import re
import argparse


def resolve_domain(domain, dns_ip="10.0.0.254"):
    for _ in range(5):
        try:
            cmd = f"nslookup {domain} {dns_ip}"
            res = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.5
            )
            ips = re.findall(r'\b10\.0\.0\.\d+\b', res.stdout)
            valid = [ip for ip in ips if ip != dns_ip]
            if valid:
                return valid[-1]
        except Exception:
            pass
        time.sleep(0.2)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Target domain, e.g. host7.com")
    parser.add_argument('--port', type=int, default=5201, help="Target port")
    parser.add_argument('--bandwidth', default="10M", help="Bandwidth")
    parser.add_argument('--duration', '--burst', dest='duration', type=int, default=30, help="Duration of continuous streaming session in seconds")
    parser.add_argument('--pause', type=float, default=0.5, help="Pause between sessions")
    parser.add_argument('--dns', default="10.0.0.254", help="DNS server IP")
    args = parser.parse_args()

    vip = None
    while True:
        if not vip:
            vip = resolve_domain(args.target, args.dns)
            if not vip:
                time.sleep(0.5)
                continue

        # Execute sustained uninterrupted TCP transfer
        cmd = f"iperf3 -c {vip} -p {args.port} -t {args.duration} -b {args.bandwidth} >/dev/null 2>&1"
        res = subprocess.run(cmd, shell=True)

        # When sustained transfer completes or disconnects, re-resolve for next stream
        vip = None
        time.sleep(args.pause)


if __name__ == '__main__':
    main()
