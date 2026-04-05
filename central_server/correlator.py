import time
from typing import Dict, Optional, Tuple, List, Any
from models import NormalizedEvent, FinalAlert
from storage import db


class Correlator:
    def __init__(self, time_window_seconds: float = 5.0):
        self.time_window = time_window_seconds
        # Key: (src_ip, dest_ip, type, subtype)
        self.event_cache: Dict[Tuple[str, str, str, Optional[str]], List[Any]] = {}

    def _cleanup_old_events(self, current_time: float):
        keys_to_remove = []
        for key, value in self.event_cache.items():
            first_event_time = value[2]
            if current_time - first_event_time > self.time_window:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del self.event_cache[key]

    def process_event(self, new_event: NormalizedEvent) -> Optional[FinalAlert]:
        current_time = time.time()
        self._cleanup_old_events(current_time)

        # Determine target key
        target_key = None
        if new_event.source == "AIDS":
            for key in self.event_cache.keys():
                if key[0] == new_event.src_ip and key[1] == new_event.dest_ip and key[2] == new_event.type:
                    target_key = key
                    break
            if not target_key:
                target_key = (new_event.src_ip, new_event.dest_ip, new_event.type, None)
        else:
            # SIDS
            exact_key = (new_event.src_ip, new_event.dest_ip, new_event.type, new_event.subtype)
            aids_key = (new_event.src_ip, new_event.dest_ip, new_event.type, None)

            if exact_key in self.event_cache:
                target_key = exact_key
            elif aids_key in self.event_cache:
                # Upgrade AIDS key to exact_key
                self.event_cache[exact_key] = self.event_cache.pop(aids_key)
                target_key = exact_key
            else:
                target_key = exact_key

        if target_key not in self.event_cache:
            # Initialize with empty slots: [sids, aids, timestamp, final_alert]
            self.event_cache[target_key] = [None, None, current_time, None]

        cached_data = self.event_cache[target_key]

        # Determine the source and update cache
        if new_event.source == "SIDS":
            cached_data[0] = new_event
        elif new_event.source == "AIDS":
            cached_data[1] = new_event

        sids_ev = cached_data[0]
        aids_ev = cached_data[1]

        # Prepare the fields
        detected_by = []
        confidence = None
        subtype = None
        severity = None
        src_port = None
        dest_port = None
        signature = None
        category = None

        if sids_ev:
            detected_by.append("SIDS")
            subtype = sids_ev.subtype
            severity = sids_ev.severity
            src_port = sids_ev.src_port
            dest_port = sids_ev.dest_port
            signature = sids_ev.signature
            category = sids_ev.category
        if aids_ev:
            detected_by.append("AIDS")
            confidence = aids_ev.confidence
            if not subtype and aids_ev.subtype:
                subtype = aids_ev.subtype

        existing_alert = cached_data[3]

        if existing_alert:
            # Update the existing alert in place
            existing_alert.detected_by = detected_by
            existing_alert.count += 1
            if confidence is not None:
                existing_alert.confidence = confidence
            if sids_ev:
                # Apply subtype and severity for late-arriving SIDS events
                existing_alert.subtype = subtype
                existing_alert.severity = severity
                existing_alert.src_port = src_port
                existing_alert.dest_port = dest_port
                existing_alert.signature = signature
                existing_alert.category = category
            if aids_ev and aids_ev.subtype and not existing_alert.subtype:
                existing_alert.subtype = aids_ev.subtype
            existing_alert.timestamp = new_event.timestamp
            return existing_alert
        else:
            # KEY FIX: Before creating a new FinalAlert, check if one already
            # exists in storage for this (src_ip, dest_ip, type, subtype) key.
            # This prevents the 5-second window expiry from creating duplicate
            # entries in the DB for the same ongoing attack stream.
            stored_alert = db.get_alert(new_event.src_ip, new_event.dest_ip, new_event.type, subtype)

            if stored_alert:
                # Reuse the existing stored object — bring it back into the active cache
                stored_alert.count += 1
                stored_alert.timestamp = new_event.timestamp
                stored_alert.detected_by = detected_by
                if confidence is not None:
                    stored_alert.confidence = confidence
                if sids_ev:
                    stored_alert.subtype = subtype
                    stored_alert.severity = severity
                    stored_alert.src_port = src_port
                    stored_alert.dest_port = dest_port
                    stored_alert.signature = signature
                    stored_alert.category = category
                if aids_ev and aids_ev.subtype and not stored_alert.subtype:
                    stored_alert.subtype = aids_ev.subtype
                cached_data[3] = stored_alert
                return stored_alert
            else:
                # Truly new attack stream — create a fresh FinalAlert
                alert = FinalAlert(
                    timestamp=new_event.timestamp,
                    src_ip=new_event.src_ip,
                    src_port=src_port,
                    dest_ip=new_event.dest_ip,
                    dest_port=dest_port,
                    type=new_event.type,
                    subtype=subtype,
                    severity=severity,
                    signature=signature,
                    category=category,
                    detected_by=detected_by,
                    alert=True,
                    confidence=confidence
                )
                cached_data[3] = alert
                # save_final_alert returns canonical object (same as alert since key is new)
                db.save_final_alert(alert)
                return alert


correlator = Correlator()
