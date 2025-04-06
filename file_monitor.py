# file_monitor.py
import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import get_file_hash, log_alert
from config import MONITORED_DIRECTORY, RESTRICTED_EXTENSIONS

class FileMonitorHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            file_name = os.path.basename(file_path)
            file_extension = os.path.splitext(file_name)[1].lower()
            file_size = os.path.getsize(file_path)
            creation_time = time.ctime(os.path.getctime(file_path))
            file_hash = get_file_hash(file_path)

            # Log file details
            log_message = (
                f"File created: {file_name}\n"
                f"Path: {file_path}\n"
                f"Extension: {file_extension}\n"
                f"Size: {file_size} bytes\n"
                f"Created on: {creation_time}\n"
                f"SHA-256 Hash: {file_hash}"
            )
            logging.info(log_message)
            print(log_message)

            # Check if file extension is restricted
            if file_extension in RESTRICTED_EXTENSIONS:
                log_alert(
                    "restricted_file_extension",
                    file_path,
                    f"Restricted file extension detected: {file_extension} | {log_message}"
                )

def start_file_monitoring():
    print(f"Monitoring directory: {MONITORED_DIRECTORY}")
    event_handler = FileMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, MONITORED_DIRECTORY, recursive=True)
    observer.start()
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
