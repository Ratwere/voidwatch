from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.decision import Action, decide_action
from app.detection import detect_untrusted_content
from app.honeypot import (
    HoneypotAction,
    get_honeypot_context,
    list_honeypot_events,
    record_honeypot_action,
)


app = FastAPI(title="PlutoHacks Shield")


class CheckRequest(BaseModel):
    content: str


class CheckResponse(BaseModel):
    score: int
    action: Action
    reason: str
    honeypot_context: dict[str, object] | None = None


class HoneypotActionRequest(BaseModel):
    action: HoneypotAction
    target: str = Field(min_length=1, max_length=2048)
    payload: str = Field(default="", max_length=10000)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse, response_model_exclude_none=True)
def check_content(request: CheckRequest) -> CheckResponse:
    result = detect_untrusted_content(request.content)
    action = decide_action(result.score)
    return CheckResponse(
        score=result.score,
        action=action,
        reason=result.reason,
        honeypot_context=get_honeypot_context() if action == "deceive" else None,
    )


@app.get("/honeypot/context")
def honeypot_context() -> dict[str, object]:
    return get_honeypot_context()


@app.post("/honeypot/actions")
def log_honeypot_action(request: HoneypotActionRequest) -> dict[str, object]:
    event = record_honeypot_action(
        action=request.action,
        target=request.target,
        payload=request.payload,
    )
    return event.__dict__


@app.get("/honeypot/actions")
def honeypot_actions() -> list[dict[str, object]]:
    return list_honeypot_events()
