import json
import time
import requests
import random
from datetime import datetime

URL = "http://localhost:8000/alert"

def generate_mock_aids_event():
    """Generates a random mock AIDS event."""
    # Sometimes generate an event that matches Suricata signatures,
    # sometimes generate entirely random anomalies.
    
    ips = ["10.42.0.231", "10.42.0.150", "192.168.1.100", "192.168.1.105"]
    types = ["DOS", "RECON", "UNKNOWN_ANOMALY"]
    
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": random.choice(ips),
        "dest_ip": random.choice(ips),
        "type": random.choice(types),
        "source": "AIDS",
        "confidence": round(random.uniform(0.7, 0.99), 2)
    }
    
    # Ensure src and dest are different
    while event["src_ip"] == event["dest_ip"]:
        event["dest_ip"] = random.choice(ips)
        
    return event

def main():
    print("Starting AIDS Mock Forwarder. Generating anomalies...")
    while True:
        try:
            event = generate_mock_aids_event()
            
            response = requests.post(URL, json=event)
            print(f"Sent AIDS Event ({event['type']}) | Confidence: {event['confidence']} | Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to connect to server: {e}")
            
        # Send an event every 2 to 7 seconds
        time.sleep(random.uniform(2.0, 7.0))

if __name__ == "__main__":
    main()
