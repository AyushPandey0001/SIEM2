import logging
import time
import hashlib
import requests 
import datetime  # Add this import for logging timestamps
from config import LOG_FILENAME, LOG_SERVER_URL
from scapy.all import TCP, UDP  # Import TCP and UDP for packet details

# Configure logging
logging.basicConfig(filename=LOG_FILENAME, level=logging.INFO, format='%(asctime)s - %(message)s')
last_alert_times = {}

def log_alert(alert_type, src, message, cooldown=5):
    """Log alert with rate-limiting."""
    current_time = time.time()
    last_logged = last_alert_times.get((alert_type, src), 0)
    if current_time - last_logged >= cooldown:
        logging.warning(message)
        print(message)
        last_alert_times[(alert_type, src)] = current_time

def send_log_file(retries=3):
    """Send log file to the server with retries."""
    with open(LOG_FILENAME, 'rb') as log_file:
        for attempt in range(retries):
            try:
                response = requests.post(LOG_SERVER_URL, files={'file': (LOG_FILENAME, log_file)})
                if response.ok:
                    print(f'Log file sent: {response.status_code} - {response.text}')
                    break
            except Exception as e:
                print(f'Error sending log file: {e}')
                time.sleep(1)

def get_file_hash(file_path):
    """Calculate the SHA-256 hash of a file for integrity checking."""
    hash_func = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()
    
def print_packet_details(packet, src, dst, proto):
    """Print and log essential packet details for quick analysis."""
    port_info = ""
    if TCP in packet:
        port_info = f" | TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}"
    elif UDP in packet:
        port_info = f" | UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}"

    # Log message with brief packet details
    log_message = f"Packet captured: {src} -> {dst} | Protocol: {proto}{port_info}"
    logging.info(log_message)
    print(log_message)  # Also print to console for real-time monitoring


