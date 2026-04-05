from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from models import SIDSEvent, AIDSEvent, NormalizedEvent, FinalAlert
from normalizer import normalize_sids, normalize_aids
from correlator import correlator
from typing import List, Dict

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(title="Hybrid IDS Central Server")

# Get absolute path to dashboard directory
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

@app.get("/dashboard")
async def get_dashboard():
    """
    Serves the main dashboard HTML file.
    """
    return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))

@app.post("/alert")
async def receive_alert(event: Dict):
    """
    Receives alerts from either SIDS or AIDS.
    Requires 'source' field in JSON to determine origin.
    """
    source = event.get("source")
    
    if not source:
        raise HTTPException(status_code=400, detail="Missing 'source' field in event")
        
    try:
        if source == "SIDS":
            sids_evt = SIDSEvent(**event)
            normalized_evt = normalize_sids(sids_evt)
        elif source == "AIDS":
            aids_evt = AIDSEvent(**event)
            normalized_evt = normalize_aids(aids_evt)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown source: {source}")
            
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    # Process through correlator
    final_alert = correlator.process_event(normalized_evt)
    
    return {"message": "Event processed", "alert": final_alert}

@app.get("/events", response_model=List[FinalAlert])
async def get_events(limit: int = 100):
    """
    Returns the most recent correlated final alerts (one per unique attack stream).
    """
    from storage import db
    return db.get_alerts(limit)  # Already sorted newest-first by storage

from datetime import datetime, timedelta
from collections import defaultdict

@app.get("/stats/overview")
async def get_stats_overview():
    from storage import db
    alerts = db.get_all_alerts()
    total = sum(a.count for a in alerts)
    
    now = datetime.now()
    recent_alerts = 0
    types_set = set()
    for a in alerts:
        types_set.add(a.type)
        try:
            dt_str = a.timestamp.replace('Z', '')
            dt = datetime.fromisoformat(dt_str).replace(tzinfo=None)
            
            if (now - dt).total_seconds() <= 10:
                recent_alerts += a.count
        except:
            pass
            
    aps = recent_alerts / 10.0
    threat_level = "LOW"
    if aps > 10:
        threat_level = "HIGH"
    elif aps > 5:
        threat_level = "MEDIUM"
        
    return {
        "total_alerts": total,
        "attacks": total,
        "normal": 0,
        "active_types": len(types_set),
        "alerts_per_sec": float(f"{aps:.2f}"),
        "threat_level": threat_level
    }

@app.get("/stats/types")
async def get_stats_types():
    from storage import db
    counts = {}
    for a in db.get_all_alerts():
        t = a.type.upper()
        counts[t] = counts.get(t, 0) + a.count
    return counts

@app.get("/stats/subtypes")
async def get_stats_subtypes():
    from storage import db
    counts = defaultdict(int)
    for a in db.get_all_alerts():
        st = a.subtype if a.subtype else "N/A"
        counts[st] += a.count
    return dict(counts)

@app.get("/stats/timeline")
async def get_stats_timeline():
    from storage import db
    now = datetime.now()
    cutoff = now - timedelta(seconds=60)
    
    buckets = defaultdict(lambda: {"total": 0, "DOS": 0, "RECON": 0, "SQLI": 0})
    for a in reversed(db.get_all_alerts()):
        try:
            dt_str = a.timestamp.replace('Z', '')
            dt = datetime.fromisoformat(dt_str).replace(tzinfo=None)
                
            if dt < cutoff:
                break
            time_str = dt.strftime("%H:%M:%S")
            buckets[time_str]["total"] += a.count
            t = a.type.upper()
            if t in buckets[time_str]:
                buckets[time_str][t] += a.count
        except:
            pass
            
    timeline = []
    for i in range(60, -1, -1):
        t = (now - timedelta(seconds=i)).strftime("%H:%M:%S")
        b = buckets.get(t, {"total": 0, "DOS": 0, "RECON": 0, "SQLI": 0})
        timeline.append({
            "time": t, 
            "total": b["total"],
            "dos": b.get("DOS", 0),
            "recon": b.get("RECON", 0),
            "sqli": b.get("SQLI", 0)
        })
        
    return timeline

@app.get("/stats/top_attackers")
async def get_stats_attackers():
    from storage import db
    counts = defaultdict(int)
    for a in db.get_all_alerts():
        counts[a.src_ip] += a.count
    
    sorted_attackers = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"src_ip": ip, "count": c} for ip, c in sorted_attackers]

@app.get("/stats/connections")
async def get_stats_connections():
    from storage import db
    conn = defaultdict(lambda: {"count": 0, "type": set()})
    for a in db.get_all_alerts():
        port_str = f":{a.dest_port}" if a.dest_port else ""
        key = f"{a.src_ip} -> {a.dest_ip}{port_str}"
        conn[key]["count"] += a.count
        conn[key]["type"].add(a.type)
        
    result = []
    for k, v in conn.items():
        src, dest = k.split(" -> ")
        result.append({
            "src_ip": src,
            "dest_ip": dest,
            "type": ", ".join(sorted(v["type"])), # sort types for consistent rendering
            "count": v["count"]
        })
    return sorted(result, key=lambda x: x["count"], reverse=True)

@app.get("/stats/engines")
async def get_stats_engines():
    from storage import db
    counts = {"SIDS": 0, "AIDS": 0, "HYBRID": 0}
    for a in db.get_all_alerts():
        if len(a.detected_by) > 1:
            counts["HYBRID"] += a.count
        elif "SIDS" in a.detected_by:
            counts["SIDS"] += a.count
        else:
            counts["AIDS"] += a.count
    return counts

@app.get("/health")
async def health_check():
    """
    System status endpoint.
    """
    return {"status": "ok", "service": "Hybrid IDS Central Server"}

@app.post("/reset")
async def reset_data():
    """
    Clears all in-memory alerts and resets the correlator cache.
    """
    from storage import db
    db.clear_all()
    correlator.event_cache.clear()
    return {"message": "All data cleared successfully"}

# Run with: uvicorn main:app --reload
