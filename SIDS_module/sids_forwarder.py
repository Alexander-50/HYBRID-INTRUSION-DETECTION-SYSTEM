import json
import os
import time
import requests
import sys
from datetime import datetime, timedelta, timezone

URL = "http://localhost:8000/alert"
HEALTH_URL = "http://localhost:8000/health"
DATASET_FILE = "/home/whoami/Desktop/HYBRID_IDS/SIDS_module/labeled_dataset.json"
STALE_GRACE_SECONDS = 10

def open_dataset():
    file = open(DATASET_FILE, "r")
    stat = os.fstat(file.fileno())
    return file, stat.st_ino

def read_next_line(file, expected_inode):
    """
    Read a single appended line, waiting until one is available.
    If the dataset file is truncated or replaced, signal the caller so it can
    reopen the fresh file handle from the beginning.
    """
    while True:
        try:
            current_stat = os.stat(DATASET_FILE)
        except FileNotFoundError:
            time.sleep(0.5)
            continue

        current_pos = file.tell()
        if current_stat.st_ino != expected_inode or current_stat.st_size < current_pos:
            return None

        line = file.readline()
        if line:
            return line
        time.sleep(0.5)

def parse_event_timestamp(raw_timestamp):
    if not raw_timestamp:
        return None

    try:
        return datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None

def wait_for_server():
    """Block until the central server is reachable again."""
    while True:
        try:
            response = requests.get(HEALTH_URL, timeout=3)
            response.raise_for_status()
            return
        except requests.exceptions.RequestException as exc:
            print(f"Central server still unavailable: {exc}")
            time.sleep(2)

def is_stale_event(event, cutoff_time):
    event_time = parse_event_timestamp(event.get("timestamp"))
    if event_time is None:
        return False
    return event_time < cutoff_time

def main():
    print(f"Starting SIDS Forwarder. Tailing {DATASET_FILE}")
    try:
        f, current_inode = open_dataset()
        try:
            # Only follow events that arrive after this process becomes active.
            f.seek(0, 2)
            cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=STALE_GRACE_SECONDS)

            while True:
                line = read_next_line(f, current_inode)
                if line is None:
                    print("Detected labeled_dataset reset/rotation. Reopening fresh file.")
                    f.close()
                    f, current_inode = open_dataset()
                    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=STALE_GRACE_SECONDS)
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    print(f"Error decoding JSON: {line}")
                    continue

                if is_stale_event(event, cutoff_time):
                    print(
                        "Skipping stale SIDS event "
                        f"({event.get('subtype', 'UNKNOWN')}) from {event.get('timestamp')}"
                    )
                    continue

                try:
                    response = requests.post(URL, json=event, timeout=3)
                    response.raise_for_status()
                    print(
                        "Sent SIDS Event "
                        f"({event.get('subtype', 'UNKNOWN')}) | Status: {response.status_code}"
                    )
                except requests.exceptions.RequestException as e:
                    print(f"Failed to connect to server: {e}")
                    wait_for_server()
                    # Drop any backlog accumulated while the server was down.
                    f.seek(0, 2)
                    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=STALE_GRACE_SECONDS)
                    print("Central server recovered. Resynced SIDS forwarder to EOF.")
                    continue

                time.sleep(0.1) # Simulate slight network delay
        finally:
            f.close()
    except FileNotFoundError:
        print(f"Error: {DATASET_FILE} not found. Please ensure Suricata output is generating this file.")
        sys.exit(1)

if __name__ == "__main__":
    main()
