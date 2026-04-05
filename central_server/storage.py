from typing import List, Dict, Tuple, Optional
from models import NormalizedEvent, FinalAlert


class Storage:
    def __init__(self):
        self.raw_events: List[NormalizedEvent] = []
        # KEY FIX: use a dict keyed by (src_ip, dest_ip, type, subtype)
        # This ensures ONE canonical FinalAlert per unique attack stream,
        # instead of spamming a new entry every 5-second correlator window.
        self._alert_map: Dict[Tuple, FinalAlert] = {}

    def _key(self, src_ip: str, dest_ip: str, type_: str, subtype: Optional[str]) -> Tuple:
        return (src_ip, dest_ip, type_, subtype or "")

    def save_raw_event(self, event: NormalizedEvent):
        self.raw_events.append(event)

    def save_final_alert(self, alert: FinalAlert) -> FinalAlert:
        """
        Upsert: merge with existing alert for same (src, dest, type, subtype).
        Returns the canonical stored object so the caller can hold a reference to it.
        """
        key = self._key(alert.src_ip, alert.dest_ip, alert.type, alert.subtype)
        if key in self._alert_map:
            existing = self._alert_map[key]
            # Update mutable fields — the correlator already manages count directly
            # on the object reference, so we just sync metadata here.
            existing.timestamp = alert.timestamp
            for det in alert.detected_by:
                if det not in existing.detected_by:
                    existing.detected_by.append(det)
            if alert.confidence is not None:
                existing.confidence = alert.confidence
            if alert.severity is not None:
                existing.severity = alert.severity
            if alert.signature:
                existing.signature = alert.signature
            if alert.category:
                existing.category = alert.category
            if alert.subtype and not existing.subtype:
                existing.subtype = alert.subtype
            return existing
        else:
            self._alert_map[key] = alert
            return alert

    def get_alert(self, src_ip: str, dest_ip: str, type_: str, subtype: Optional[str]) -> Optional[FinalAlert]:
        """Look up a stored alert by its unique key."""
        return self._alert_map.get(self._key(src_ip, dest_ip, type_, subtype))

    def get_alerts(self, limit: int = 100) -> List[FinalAlert]:
        """Return the most recently active alerts, newest first."""
        sorted_alerts = sorted(self._alert_map.values(), key=lambda a: a.timestamp, reverse=True)
        return sorted_alerts[:limit]

    def get_raw_events(self, limit: int = 100) -> List[NormalizedEvent]:
        return self.raw_events[-limit:]

    def get_all_alerts(self) -> List[FinalAlert]:
        return list(self._alert_map.values())

    def clear_all(self):
        self._alert_map.clear()
        self.raw_events.clear()


# Singleton instance
db = Storage()
