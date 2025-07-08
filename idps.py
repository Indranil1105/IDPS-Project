import os
import sys
import time
import fnmatch
import threading
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileModifiedEvent
)
from monitor import monitor_network_connections, monitor_system_processes
from anomaly_detector import AdvancedAnomalyDetector

# Ensure logs and quarantine directories exist
os.makedirs("./logs", exist_ok=True)
os.makedirs("./quarantine", exist_ok=True)

class IDPSEventHandler(FileSystemEventHandler):
    """Enhanced file system event handler with anomaly detection and prevention."""

    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector or AdvancedAnomalyDetector()

    def _get_event_type(self, event):
        return {
            FileCreatedEvent: 0,
            FileDeletedEvent: 1,
            FileMovedEvent: 2,
            FileModifiedEvent: 3
        }.get(type(event), -1)

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None
        file_size = os.path.getsize(event.src_path) if os.path.exists(event.src_path) else 0
        return [event_type, file_size]

    def should_ignore(self, path):
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.ignore_patterns)

    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def log_prevention(self, action, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("./logs/prevention_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - PREVENTION: {action} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        self._process_event(event, "created")

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        self._process_event(event, "deleted")

    def on_moved(self, event):
        if self.should_ignore(event.src_path) or self.should_ignore(event.dest_path):
            return
        self._process_event(event, "moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        self._process_event(event, "modified")

    def _process_event(self, event, action, details=None):
        feature_vector = self._get_event_vector(event)
        is_anomaly = False
        if feature_vector:
            is_anomaly = self.anomaly_detector.add_event(feature_vector)
        path = details if details else event.src_path
        print(f"Alert! {path} has been {action}.")
        self.log_event(action, path)

        # === PREVENTION LOGIC ===
        if is_anomaly and action in ["created", "modified"]:
            quarantine_dir = "./quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            try:
                if os.path.exists(event.src_path):
                    dest = os.path.join(quarantine_dir, os.path.basename(event.src_path))
                    os.rename(event.src_path, dest)
                    print(f"Prevention: {event.src_path} moved to quarantine.")
                    self.log_prevention("quarantine", event.src_path)
            except Exception as e:
                print(f"Failed to quarantine {event.src_path}: {e}")

def main():
    paths = ["./lab"]
    os.makedirs('./lab', exist_ok=True)
    ignore_patterns = ["*.tmp", "*.log"]

    # Initialize components
    anomaly_detector = AdvancedAnomalyDetector(threshold=10, time_window=60)
    event_handler = IDPSEventHandler(ignore_patterns=ignore_patterns, anomaly_detector=anomaly_detector)
    observer = Observer()

    # Configure observer
    for path in paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
        else:
            print(f"Warning: Monitoring path {path} does not exist!")

    # Start monitoring threads
    observer.start()

    network_monitor_thread = threading.Thread(
        target=monitor_network_connections,
        daemon=True
    )
    network_monitor_thread.start()

    process_monitor_thread = threading.Thread(
        target=monitor_system_processes,
        daemon=True
    )
    process_monitor_thread.start()

    # Main loop
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down IDPS...")
    finally:
        observer.stop()
        observer.join()
        print("IDPS stopped.")

if __name__ == "__main__":
    main()
