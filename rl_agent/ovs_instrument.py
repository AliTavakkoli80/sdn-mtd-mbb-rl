import subprocess
import re

def dump_total_flow_count(switches=("s1", "s2", "s3", "s4")):
    """
    Return total number of flow entries across all switches (sum over tables).
    Uses 'ovs-ofctl dump-aggregate <sw> -O OpenFlow13'.
    Parses 'flow_count=<N>' or 'flow_count:<N>'.
    """
    total = 0
    cmd_base = ["sudo", "-n", "ovs-ofctl"]
    for sw in switches:
        try:
            out = subprocess.check_output(
                cmd_base + ["dump-aggregate", sw, "-O", "OpenFlow13"],
                text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                m = re.search(r'flow_count[=:]\s*(\d+)', line)
                if m:
                    total += int(m.group(1))
        except Exception:
            # Switch may not exist or not be reachable
            pass
    return total

def dump_active_translation_flows(switches=("s1", "s2", "s3", "s4")):
    """
    Count flows in TABLE_ACTIVE (table 0) specifically across all switches.
    """
    total = 0
    cmd_base = ["sudo", "-n", "ovs-ofctl"]
    for sw in switches:
        try:
            out = subprocess.check_output(
                cmd_base + ["dump-flows", sw, "table=0", "-O", "OpenFlow13"],
                text=True, stderr=subprocess.DEVNULL
            )
            for line in out.strip().splitlines():
                if "table=0" in line or "actions=" in line:
                    total += 1
        except Exception:
            pass
    return total

if __name__ == "__main__":
    count = dump_total_flow_count()
    t0_count = dump_active_translation_flows()
    print(f"Total OVS Flows: {count}, Table 0 Flows: {t0_count}")
