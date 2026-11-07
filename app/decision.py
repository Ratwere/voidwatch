from typing import Literal

Action = Literal["allow", "deceive", "block"]

ALLOW_MAX_SCORE = 30
DECEIVE_MAX_SCORE = 70


def decide_action(score: int) -> Action:
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    if score <= ALLOW_MAX_SCORE:
        return "allow"
    if score <= DECEIVE_MAX_SCORE:
        return "deceive"
    return "block"
