from datetime import datetime
from models import SIDSEvent, AIDSEvent, NormalizedEvent

SUBTYPE_MAPPING = {
    "PING FLOOD": "DOS-ICMP-FLOOD",
    "PING-FLOOD": "DOS-ICMP-FLOOD",
    "SYN FLOOD": "DOS-SYN-FLOOD",
    "SYN-FLOOD": "DOS-SYN-FLOOD",
    "ACK FLOOD": "DOS-ACK-FLOOD",
    "ACK-FLOOD": "DOS-ACK-FLOOD",
    "UDP FLOOD": "DOS-UDP-FLOOD",
    "UDP-FLOOD": "DOS-UDP-FLOOD",
    "TCP FLOOD": "DOS-TCP-FLOOD",
    "TCP-FLOOD": "DOS-TCP-FLOOD",
}

def _normalize_subtype(subtype: str) -> str:
    if not subtype:
        return None
    s = subtype.strip().upper()
    return SUBTYPE_MAPPING.get(s, s)

def _normalize_timestamp(timestamp: str | None) -> str:
    """
    Preserve the source event time when available so the dashboard ordering
    reflects when the sensor actually detected the alert, not when the central
    server happened to ingest it.
    """
    if not timestamp:
        return datetime.now().isoformat()

    cleaned = timestamp.strip()
    if not cleaned:
        return datetime.now().isoformat()

    # Keep valid source timestamps, including Suricata's timezone offsets.
    try:
        datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        return cleaned
    except ValueError:
        return datetime.now().isoformat()

def normalize_sids(event: SIDSEvent) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_normalize_timestamp(event.timestamp),
        src_ip=event.src_ip,
        src_port=event.src_port,
        dest_ip=event.dest_ip,
        dest_port=event.dest_port,
        type=event.type.upper(),
        subtype=_normalize_subtype(event.subtype),
        severity=event.severity,
        signature=event.signature,
        category=event.category,
        source=event.source,
        confidence=None
    )

def normalize_aids(event: AIDSEvent) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=_normalize_timestamp(event.timestamp),
        src_ip=event.src_ip,
        src_port=None,
        dest_ip=event.dest_ip,
        dest_port=None,
        type=event.type.upper(),
        subtype=_normalize_subtype(event.subtype),
        severity=None,
        signature=None,
        category=None,
        source=event.source,
        confidence=event.confidence
    )
