"""System prompts for /understand multi-model dispatch.

Prompts live as Python module-level strings rather than markdown so:
- They're versioned with the dispatch code (no skill-prose drift).
- Tests can import them.

The prompts are passed VERBATIM as the system string — no
interpolation of any kind (the brace-shaped text inside them is
literal JSON-schema prose, not placeholders). Run-specific context
travels in the user message, never by formatting the system prompt.
"""

from packages.code_understanding.prompts.hunt_system import HUNT_SYSTEM_PROMPT
from packages.code_understanding.prompts.trace_system import TRACE_SYSTEM_PROMPT

__all__ = [
    "HUNT_SYSTEM_PROMPT",
    "TRACE_SYSTEM_PROMPT",
]
