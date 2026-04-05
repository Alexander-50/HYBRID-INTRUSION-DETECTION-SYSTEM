import requests
import time
from datetime import datetime

URL = "http://localhost:8000/alert"

def simulate():
    ts = datetime.utcnow().isoformat()
    # SIDS Event
    sids = {
        "timestamp": ts, "src_ip": "10.0.0.1", "src_port": 1234,
        "dest_ip": "10.0.0.2", "dest_port": 80, "type": "DOS",
        "subtype": "SYN FLOOD", "source": "SIDS", "label": "attack"
    }
    # AIDS Event
    aids = {
        "timestamp": ts, "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2",
        "type": "DOS", "source": "AIDS", "confidence": 0.95
    }
    
    print("Sending SIDS...")
    requests.post(URL, json=sids)
    time.sleep(0.5)
    print("Sending AIDS...")
    requests.post(URL, json=aids)
    
if __name__ == "__main__":
    simulate()
