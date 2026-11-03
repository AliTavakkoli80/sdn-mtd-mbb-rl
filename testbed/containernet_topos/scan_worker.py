#!/usr/bin/env python3
"""
scan_worker.py - Scanner worker executed inside attacker container (mn.h1).
Issues real TCP connect/SYN probes and raw ARP requests against resolved VIPs
and logs empirical results to /tmp/attacker_scan_results.json as:
[{"target": vip, "port": p, "status": "OPEN"|"CLOSED"|"FILTERED"|"TIMEOUT"}, ...]
"""

import sys
import time
import json
import socket
import struct
import fcntl
import os
import argparse

def get_default_interface():
    try:
        devs = [d for d in os.listdir('/sys/class/net') if d != 'lo']
        # Prioritize SDN / Containernet host interface (e.g. h1-eth0)
        for d in devs:
            if '-eth0' in d or d.startswith('h'):
                return d
        for d in devs:
            if d != 'eth0':
                return d
        if devs:
            return devs[0]
    except Exception:
        pass
    return 'h1-eth0'

def get_iface_info(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        src_ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        src_ip = "10.0.0.1"
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode('utf-8')))
        src_mac = info[18:24]
    except Exception:
        src_mac = b'\x00' * 6
    s.close()
    return src_ip, src_mac

def send_raw_arp(iface, src_ip, src_mac, target_ip):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, 0))
        eth_hdr = struct.pack("!6s6sH", b"\xff\xff\xff\xff\xff\xff", src_mac, 0x0806)
        arp_payload = struct.pack(
            "!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 1,
            src_mac, socket.inet_aton(src_ip),
            b"\x00" * 6, socket.inet_aton(target_ip)
        )
        s.send(eth_hdr + arp_payload)
        s.close()
    except Exception:
        pass

def probe_single(target, port=80, timeout=0.15, iface=None, src_ip=None, src_mac=None):
    # 1. ARP sweep trigger for SDN threat detection
    if iface and src_ip and src_mac:
        send_raw_arp(iface, src_ip, src_mac, str(target))

    # 2. TCP connect probe
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    status = "FILTERED"
    try:
        s.connect((target, port))
        status = "OPEN"
    except socket.timeout:
        status = "TIMEOUT"
    except ConnectionRefusedError:
        status = "CLOSED"
    except OSError as e:
        err = str(e).lower()
        if "unreachable" in err or "timeout" in err:
            status = "TIMEOUT"
        elif "refused" in err:
            status = "CLOSED"
        else:
            status = "FILTERED"
    except Exception:
        status = "FILTERED"
    finally:
        try:
            s.close()
        except Exception:
            pass

    return {
        "target": target,
        "port": port,
        "status": status
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vips', nargs='+', required=True)
    parser.add_argument('--ports', nargs='+', type=int, default=[80])
    parser.add_argument('--interface', default=None)
    parser.add_argument('--output', default='/tmp/attacker_scan_results.json')
    parser.add_argument('--interval', type=float, default=0.10)
    args = parser.parse_args()

    vips = args.vips
    ports = args.ports
    results_file = args.output
    iface = args.interface or get_default_interface()
    src_ip, src_mac = get_iface_info(iface)

    print(f"[*] scan_worker started on iface={iface} ({src_ip}), targets={vips}, ports={ports}, output={results_file}", flush=True)

    targets_to_probe = [(vip, p) for vip in vips for p in ports]
    n_targets = max(len(targets_to_probe), 1)
    delay = max(args.interval / n_targets, 0.01)

    while True:
        probe_records = []
        for vip, p in targets_to_probe:
            rec = probe_single(vip, p, 0.15, iface, src_ip, src_mac)
            probe_records.append(rec)
            time.sleep(delay)

        # Write directly to results file with atomic replacement
        try:
            tmp_file = f"{results_file}.tmp"
            with open(tmp_file, "w") as f:
                json.dump(probe_records, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, results_file)
        except Exception:
            try:
                with open(results_file, "w") as f:
                    json.dump(probe_records, f)
                    f.flush()
            except Exception:
                pass

if __name__ == '__main__':
    main()
