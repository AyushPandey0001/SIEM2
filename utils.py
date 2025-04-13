import logging

# Setup logging
logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_alert(alert_type, source, description):
    message = f"[{alert_type.upper()}] Source: {source} | {description}"
    print(message)
    logging.warning(message)

def print_packet_details(packet, src, dst, proto):
    summary = f"Packet: {src} -> {dst} | Protocol: {proto}"
    print(summary)
    logging.info(summary)
