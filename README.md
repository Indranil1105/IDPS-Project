# IDPS Project


An Intrusion Detection and Prevention System (IDPS) implemented in Python. It monitors file system activities, network connections, and system processes in real time, detects anomalies using machine learning, and automatically prevents malicious or abnormal behavior by quarantining files or terminating offending processes.


## Features

### Real-Time File Monitoring
Watches create, delete, move, and modify events under specified directories.

### Anomaly Detection
Uses an Isolation Forest model to identify unusual file‐system event patterns.

### Automated Prevention
Quarantines suspicious files and terminates processes exceeding resource thresholds.

### Network Connection Logging
Detects and logs new remote connections.

### Process Resource Monitoring
Tracks CPU/memory usage; kills processes that abuse configured thresholds.

### Extensible Configuration
Adjustable thresholds, ignore patterns, and time windows via constructor parameters.

## Requirements

Python 3.8 or higher

watchdog

psutil

numpy

scikit-learn

## Install dependencies:

pip install -r requirements.txt

## Installation

### Clone the repository

git clone [https://github.com/Indranil1105/IDPS-Project.git](https://github.com/Indranil1105/IDPS-Project.git)
cd idps

### Install dependencies

pip install -r requirements.txt

### Create required directories


mkdir logs quarantine lab

## Usage

Run the main script to start monitoring:

### python idps.py
By default, it monitors the ./lab directory. To change monitored paths or ignore patterns, modify the main() function in idps.py.

### Command-Line Options (Future)
Currently no CLI flags; configuration via code. CLI support planned in future releases.

## Configuration
In idps.py:

anomaly_detector = AdvancedAnomalyDetector(

    threshold=10,        # Minimum samples before training
    
    time_window=60,      # Seconds window for event queue
    
    train_interval=30    # Seconds between retraining
    
)

ignore_patterns = ["*.tmp", "*.log"]

paths = ["./lab", "/path/to/other/dir"]

Adjust cpu_threshold and mem_threshold in monitor.py for process monitoring.

## Logs & Quarantine

Logs saved under ./logs/:

file_log.txt

network_connections_log.txt

processes_log.txt

prevention_log.txt

Quarantine: Suspicious files moved to ./quarantine/.

## Project Structure

├── anomaly_detector.py      # Isolation Forest based detector

├── idps.py                  # Main system orchestrator

├── monitor.py               # Network & process monitors

├── requirements.txt         # Python dependencies

└── logs/                    # Runtime logs

└── quarantine/              # Quarantined files

## Security Considerations

### Permissions: Run with appropriate privileges to allow file renaming and process termination.

### False Positives: Review logs and adjust thresholds to minimize unintended quarantines or kills.

### Resource Usage: Continuous monitoring may consume CPU; consider running on dedicated hosts.

