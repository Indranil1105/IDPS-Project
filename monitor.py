import os
import time
import psutil

# Ensure logs directory exists
os.makedirs("./logs", exist_ok=True)

def monitor_network_connections(interval=5, log_file="./logs/network_connections_log.txt"):
    """Monitor active network connections and log new ones."""
    previous_connections = set()
    try:
        while True:
            current_connections = set()
            for conn in psutil.net_connections(kind="inet"):
                if conn.raddr:  # Only track remote connections
                    connection_data = (
                        conn.laddr.ip if conn.laddr else None,
                        conn.laddr.port if conn.laddr else None,
                        conn.raddr.ip if conn.raddr else None,
                        conn.raddr.port if conn.raddr else None,
                        conn.status
                    )
                    current_connections.add(connection_data)
            new_connections = current_connections - previous_connections
            if new_connections:
                with open(log_file, "a") as f:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                    for conn in new_connections:
                        f.write(f"{timestamp} - {conn}\n")
            previous_connections = current_connections
            time.sleep(interval)
    except Exception as e:
        print(f"Network monitor error: {e}")

def monitor_system_processes(interval=5, cpu_threshold=20, mem_threshold=20, log_file="./logs/processes_log.txt"):
    """Monitor system processes for abnormal resource usage and take prevention action."""
    try:
        while True:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                proc.cpu_percent(interval=0.1)
                info = proc.info
                pid = info["pid"]
                name = info["name"]
                cpu = info["cpu_percent"]
                mem = info["memory_percent"]
                if cpu > cpu_threshold or mem > mem_threshold:
                    with open(log_file, "a") as f:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                        f.write(f"{timestamp} - {name} (PID: {pid}) - CPU: {cpu}%, MEM: {mem}%\n")
                    # === PREVENTION LOGIC ===
                    try:
                        proc.terminate()
                        print(f"Prevention: Terminated process {name} (PID: {pid}) for resource abuse.")
                        with open("./logs/prevention_log.txt", "a") as pf:
                            pf.write(f"{timestamp} - PREVENTION: Terminated process {name} (PID: {pid})\n")
                    except Exception as e:
                        print(f"Failed to terminate process {name} (PID: {pid}): {e}")
            time.sleep(interval)
    except Exception as e:
        print(f"Process monitor error: {e}")
