# # MTD mappings (real IP -> virtual IP)
# REAL_TO_VIRTUAL = {
#     '10.0.0.1': '10.0.0.11',
#     '10.0.0.2': '10.0.0.12'
# }

# DNS_SERVER_IP = '10.0.0.10'
# # DNS_SERVER_IP = '10.0.0.254'  # DNS on separate IP (not protected)

# # Topology discovery interval (seconds)
# TOPOLOGY_DISCOVERY_INTERVAL = 15
# TOPOLOGY_FULL_SCAN_CYCLES = 2   # every 2 intervals do a full scan



###################################################################################
# MTD mappings (real IP -> initial virtual IP)
# All 10 hosts are protected by MTD
REAL_TO_VIRTUAL = {
    '10.0.0.1': '10.0.100.1',   # h1
    '10.0.0.2': '10.0.100.2',   # h2
    '10.0.0.3': '10.0.100.3',   # h3
    '10.0.0.4': '10.0.100.4',   # h4
    '10.0.0.5': '10.0.100.5',   # h5
    '10.0.0.6': '10.0.100.6',   # h6
    '10.0.0.7': '10.0.100.7',   # h7
    '10.0.0.8': '10.0.100.8',   # h8
    '10.0.0.9': '10.0.100.9',   # h9
    '10.0.0.10': '10.0.100.10', # h10
}

# DNS Server IP (NOT protected by MTD)
DNS_SERVER_IP = '10.0.0.254'

# Hosts that should NOT be shuffled (infrastructure)
EXCLUDED_HOSTS = [DNS_SERVER_IP]

# Topology discovery interval (seconds)
TOPOLOGY_DISCOVERY_INTERVAL = 15
TOPOLOGY_FULL_SCAN_CYCLES = 2   # every 2 intervals do a full scan