# main.py
from threading import Thread
from network_monitor import start_sniffing_on_all_interfaces
from file_monitor import start_file_monitoring

def main():
    network_thread = Thread(target=start_sniffing_on_all_interfaces)
    file_thread = Thread(target=start_file_monitoring)

    network_thread.start()
    file_thread.start()

    network_thread.join()
    file_thread.join()

if __name__ == "__main__":
    main()
