LOG_FILENAME = 'network_monitor.log'
MONITORED_DIRECTORY = '../Downloads'
TRUSTED_IPS = ['127.0.0.1']
MALICIOUS_DOMAINS_FILE = 'malicious_domains.txt'
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.js']
SSH_THRESHOLD = 5
SCANNING_THRESHOLD = 10
ICMP_LARGE_PAYLOAD_SIZE = 100
HTTP_CONNECTION_THRESHOLD = 20
ALERT_COOLDOWN = 5
RESTRICTED_EXTENSIONS = ['.exe', '.bat', '.js', '.vbs', '.sh']

try:
    with open(MALICIOUS_DOMAINS_FILE, 'r') as f:
        malicious_domains = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    malicious_domains = []
