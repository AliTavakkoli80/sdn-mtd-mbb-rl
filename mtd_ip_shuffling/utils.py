import logging
import struct
import socket

def setup_logging():
    """Configure logging with custom format."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('ryu.app.mtd_ip_shuffling')

def ip_to_int(ip_str):
    """Convert IP string to integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int):
    """Convert integer to IP string."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))