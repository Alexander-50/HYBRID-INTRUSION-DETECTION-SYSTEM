import requests
import time
from datetime import datetime

URL = "http://localhost:8000/alert"

def simulate():
    ts = datetime.utcnow().isoformat()
    # SIDS Event
    sids = {
        "timestamp": ts, "src_ip": "10.42.0.231", "src_port": 1234,
        "dest_ip": "10.42.0.150", "dest_port": 80, "type": "DOS",
        "subtype": "ACK FLOOD", "source": "SIDS", "label": "attack"
    }
    # AIDS Event
    aids = {
        "timestamp": ts, "src_ip": "10.42.0.231", "dest_ip": "10.42.0.150",
        "type": "DOS", "source": "AIDS", "confidence": 0.99
    }
    
    print("Sending overlapping SIDS and AIDS...")
    requests.post(URL, json=sids)
    time.sleep(0.5)
    requests.post(URL, json=aids)
    
if __name__ == "__main__":
    simulate()
