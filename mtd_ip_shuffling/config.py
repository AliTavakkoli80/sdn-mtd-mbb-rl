# MTD mappings (real IP -> virtual IP)
REAL_TO_VIRTUAL = {
    '10.0.0.1': '10.0.0.11',
    '10.0.0.2': '10.0.0.12'
}

DNS_SERVER_IP = '10.0.0.10'

# Topology discovery interval (seconds)
TOPOLOGY_DISCOVERY_INTERVAL = 15
TOPOLOGY_FULL_SCAN_CYCLES = 2   # every 2 intervals do a full scan