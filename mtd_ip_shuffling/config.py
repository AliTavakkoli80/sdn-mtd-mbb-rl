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
# All 16 hosts in the enterprise 2-Spine 4-Leaf fabric are protected by MTD
REAL_TO_VIRTUAL = {
    '10.0.0.1': '10.0.0.101',  # h1 (Leaf 1 - Attacker)
    '10.0.0.2': '10.0.0.102',  # h2 (Leaf 1)
    '10.0.0.3': '10.0.0.103',  # h3 (Leaf 1 - Carrier)
    '10.0.0.4': '10.0.0.104',  # h4 (Leaf 1 - Carrier)
    '10.0.0.5': '10.0.0.105',  # h5 (Leaf 2)
    '10.0.0.6': '10.0.0.106',  # h6 (Leaf 2)
    '10.0.0.7': '10.0.0.107',  # h7 (Leaf 2 - Carrier)
    '10.0.0.8': '10.0.0.108',  # h8 (Leaf 2 - Carrier)
    '10.0.0.9': '10.0.0.109',  # h9 (Leaf 3)
    '10.0.0.10': '10.0.0.110', # h10 (Leaf 3)
    '10.0.0.11': '10.0.0.111', # h11 (Leaf 3)
    '10.0.0.12': '10.0.0.112', # h12 (Leaf 3)
    '10.0.0.13': '10.0.0.113', # h13 (Leaf 4)
    '10.0.0.14': '10.0.0.114', # h14 (Leaf 4)
    '10.0.0.15': '10.0.0.115', # h15 (Leaf 4)
    '10.0.0.16': '10.0.0.116', # h16 (Leaf 4)
}

# DNS Server IP (NOT protected by MTD)
DNS_SERVER_IP = '10.0.0.254'

# Hosts that should NOT be shuffled (infrastructure)
EXCLUDED_HOSTS = [DNS_SERVER_IP]

# Topology discovery interval (seconds)
TOPOLOGY_DISCOVERY_INTERVAL = 15
TOPOLOGY_FULL_SCAN_CYCLES = 2   # every 2 intervals do a full scan