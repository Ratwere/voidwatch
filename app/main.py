from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app.decision import Action, decide_action
from app.detection import detect_untrusted_content
from app.honeypot import (
    HoneypotAction,
    get_honeypot_context,
    list_honeypot_events,
    list_honeypot_events_for_check,
    record_honeypot_action,
)
from app.trail import get_check, list_checks, record_check


app = FastAPI(title="PlutoHacks Shield")


class CheckRequest(BaseModel):
    content: str


class CheckResponse(BaseModel):
    check_id: str
    score: int
    action: Action
    reason: str
    fingerprint: dict[str, str | int]
    honeypot_context: dict[str, object] | None = None


class HoneypotActionRequest(BaseModel):
    action: HoneypotAction
    target: str = Field(min_length=1, max_length=2048)
    payload: str = Field(default="", max_length=10000)
    check_id: str | None = None


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse, response_model_exclude_none=True)
def check_content(request: CheckRequest) -> CheckResponse:
    result = detect_untrusted_content(request.content)
    action = decide_action(result.score)
    event = record_check(
        content=request.content,
        score=result.score,
        action=action,
        reason=result.reason,
    )
    return CheckResponse(
        check_id=event.check_id,
        score=result.score,
        action=action,
        reason=result.reason,
        fingerprint={
            "content_sha256": event.content_sha256,
            "first_seen": event.first_seen,
            "times_seen": event.times_seen,
        },
        honeypot_context=get_honeypot_context() if action == "deceive" else None,
    )


@app.get("/honeypot/context")
def honeypot_context() -> dict[str, object]:
    return get_honeypot_context()


@app.post("/honeypot/actions")
def log_honeypot_action(request: HoneypotActionRequest) -> dict[str, object]:
    if request.check_id is not None:
        check = get_check(request.check_id)
        if check is None:
            raise HTTPException(status_code=404, detail="Check event not found")
        if check["action"] != "deceive":
            raise HTTPException(
                status_code=400,
                detail="Honeypot actions can only be linked to deceive decisions",
            )

    event = record_honeypot_action(
        action=request.action,
        target=request.target,
        payload=request.payload,
        check_id=request.check_id,
    )
    return event.__dict__


@app.get("/honeypot/actions")
def honeypot_actions() -> list[dict[str, object]]:
    return list_honeypot_events()


@app.get("/checks/{check_id}")
def check_trail(check_id: str) -> dict[str, object]:
    check = get_check(check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Check event not found")
    return {
        "check": check,
        "honeypot_actions": list_honeypot_events_for_check(check_id),
    }


@app.get("/checks")
def recent_check_trails(
    limit: int = Query(default=50, ge=1, le=100),
) -> list[dict[str, object]]:
    actions_by_check: dict[str, list[dict[str, object]]] = {}
    for action in list_honeypot_events():
        check_id = action["check_id"]
        if isinstance(check_id, str):
            actions_by_check.setdefault(check_id, []).append(action)

    return [
        {
            "check": check,
            "honeypot_actions": actions_by_check.get(str(check["check_id"]), []),
        }
        for check in list_checks(limit)
    ]
