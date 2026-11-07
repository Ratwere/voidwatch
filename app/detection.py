from dataclasses import dataclass

KNOWN_JAILBREAK_PHRASES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard all previous instructions",
    "you are now dan",
)
AI_DIRECT_ADDRESS_MARKERS = (
    "ai assistant:",
    "ai agent:",
    "to the ai:",
    "if you are an ai",
)

JAILBREAK_PHRASE_SCORE = 70
AI_DIRECT_ADDRESS_SCORE = 30


@dataclass(frozen=True)
class DetectionResult:
    score: int
    reason: str


def detect_untrusted_content(content: str) -> DetectionResult:
    normalized_content = " ".join(content.lower().split())
    score = 0
    reasons: list[str] = []

    for phrase in KNOWN_JAILBREAK_PHRASES:
        if phrase in normalized_content:
            score += JAILBREAK_PHRASE_SCORE
            reasons.append(f"Known jailbreak phrase detected: {phrase}.")
            break

    for marker in AI_DIRECT_ADDRESS_MARKERS:
        if marker in normalized_content:
            score += AI_DIRECT_ADDRESS_SCORE
            reasons.append(f"Text directly addresses an AI: {marker}.")
            break

    score = min(score, 100)
    if not reasons:
        reasons.append("No known jailbreak phrase or AI direct-address marker detected.")

    return DetectionResult(
        score=score,
        reason=" ".join(reasons),
    )
