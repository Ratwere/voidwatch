import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from app.decision import Action


@dataclass
class _Fingerprint:
    first_seen: str
    times_seen: int


@dataclass(frozen=True)
class CheckEvent:
    check_id: str
    timestamp: str
    score: int
    action: "Action"
    reason: str
    content_sha256: str
    first_seen: str
    times_seen: int


_checks: dict[str, CheckEvent] = {}
_fingerprints: dict[str, _Fingerprint] = {}
_trail_lock = Lock()


def record_check(
    content: str,
    score: int,
    action: "Action",
    reason: str,
) -> CheckEvent:
    normalized_content = " ".join(content.casefold().split())
    content_sha256 = hashlib.sha256(normalized_content.encode("utf-8")).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()

    with _trail_lock:
        fingerprint = _fingerprints.get(content_sha256)
        if fingerprint is None:
            fingerprint = _Fingerprint(first_seen=timestamp, times_seen=0)
            _fingerprints[content_sha256] = fingerprint
        fingerprint.times_seen += 1

        event = CheckEvent(
            check_id=str(uuid4()),
            timestamp=timestamp,
            score=score,
            action=action,
            reason=reason,
            content_sha256=content_sha256,
            first_seen=fingerprint.first_seen,
            times_seen=fingerprint.times_seen,
        )
        _checks[event.check_id] = event
    return event


def get_check(check_id: str) -> dict[str, object] | None:
    with _trail_lock:
        event = _checks.get(check_id)
        return asdict(event) if event is not None else None


def list_checks(limit: int) -> list[dict[str, object]]:
    with _trail_lock:
        recent_checks = sorted(
            _checks.values(),
            key=lambda event: event.timestamp,
            reverse=True,
        )[:limit]
        return [asdict(event) for event in recent_checks]
