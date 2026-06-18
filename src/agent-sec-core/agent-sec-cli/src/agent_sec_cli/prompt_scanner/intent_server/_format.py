"""Prompt-template helpers mirroring TurnGate's RLDefender training format.

The fine-tuned checkpoint at ``~/.cache/prompt_scanner/models/TurnGate/Qwen3-4B/rl_v4_best``
was trained on the *output-defense* template that takes the conversation
history together with the latest (user_query, assistant_response) pair and
emits a single digit: ``0`` for harmful, ``1`` for benign.

We reproduce the template here verbatim so the sidecar does not need to
import the upstream TurnGate repo at runtime.
"""

NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE = """You are a safety classifier. Given the conversation below, determine if the assistant's response produces harmful content (violates safety, ethics, or legal guidelines) or is benign (safe).

Conversation history:
{history}

Current exchange:
USER: {question}
ASSISTANT: {assistant_response}

Does this exchange produce harmful content? You MUST respond with ONLY a single digit and nothing else: 0 for harmful, 1 for benign. Do not include any explanation or analysis."""


def format_history(history: list[dict]) -> str:
    """Format prior turns into the ``USER: ...`` / ``ASSISTANT: ...`` block.

    Mirrors ``_format_history_for_prompt`` in
    ``TurnGate/src/defender.py``.  Empty history collapses to a placeholder
    string so the template still renders.
    """
    if not history:
        return "(No previous turns)"
    lines: list[str] = []
    for turn in history:
        role = str(turn.get("role", "unknown")).upper()
        content = turn.get("content", "")
        lines.append(f"{role}: {content}")
    return "\n\n".join(lines)


def format_defender_prompt(
    history: list[dict],
    current_query: str,
    assistant_response: str,
) -> str:
    """Format the user-content payload that gets wrapped in the chat template.

    Returns the full template-substituted string; the caller is expected to
    wrap it as ``[{"role": "user", "content": <result>}]`` and pass through
    ``tokenizer.apply_chat_template``.
    """
    return NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE.format(
        history=format_history(history),
        question=current_query,
        assistant_response=assistant_response,
    )
