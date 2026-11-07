import re
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
ZERO_WIDTH_CHARACTERS = ("\u200b", "\u200c", "\u200d", "\ufeff")
AI_IMPERATIVE_PATTERN = re.compile(
    r"(?<!ai )\b(?:ai|assistant|chatgpt)\s*[,:\-]\s*(?:please\s+)?"
    r"(?:ignore|disregard|reveal|send|forward|delete|execute|call|post|read|"
    r"open|access|upload|download|extract|summarize|follow|bypass|exfiltrate)\b"
)

JAILBREAK_PHRASE_SCORE = 70
AI_DIRECT_ADDRESS_SCORE = 30
HIDDEN_TEXT_SCORE = 35
AI_IMPERATIVE_SCORE = 35


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

    if any(character in content for character in ZERO_WIDTH_CHARACTERS):
        score += HIDDEN_TEXT_SCORE
        reasons.append("Zero-width Unicode character detected (possible hidden text).")

    if AI_IMPERATIVE_PATTERN.search(normalized_content):
        score += AI_IMPERATIVE_SCORE
        reasons.append("An imperative instruction is directly addressed to an AI.")

    score = min(score, 100)
    if not reasons:
        reasons.append(
            "No known jailbreak phrase, AI-directed instruction, or zero-width "
            "character detected."
        )

    return DetectionResult(
        score=score,
        reason=" ".join(reasons),
    )
