# config.py
from urllib.parse import urlparse

LOG_FILENAME = 'network_monitor.log'
LOG_SERVER_URL = "http://54.198.7.114/upload"
TRUSTED_IPS = ['192.168.1.1']
MALICIOUS_DOMAINS_FILE = 'malicious_domains.txt'
MONITORED_DIRECTORY = '../Downloads'
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.js']
SSH_THRESHOLD = 5
SCANNING_THRESHOLD = 10
ICMP_LARGE_PAYLOAD_SIZE = 100
HTTP_CONNECTION_THRESHOLD = 20
ALERT_COOLDOWN = 5
RESTRICTED_EXTENSIONS = ['.exe', '.bat', '.js', '.vbs', '.sh'] 

# Load malicious domains
try:
    with open(MALICIOUS_DOMAINS_FILE, 'r') as f:
        malicious_domains = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    malicious_domains = []
server_ip = urlparse(LOG_SERVER_URL).hostname
