"""
RAPTOR Autonomous Fuzzing Support

Building blocks the fuzzing pipeline composes:
- Crash prioritisation against operator goals (planner, goal_planner)
- Cross-campaign memory of strategies and crashes (memory)
- Multi-turn crash reasoning with LLMs (dialogue)
- Intelligent corpus generation (corpus_generator)
- Exploit validation (exploit_validator)

The fuzz loop itself runs on the operator's duration timer in
raptor_fuzzing.py — there is no autonomous stop-condition surface.
"""

from .planner import FuzzingPlanner, FuzzingState
from .memory import FuzzingMemory, FuzzingKnowledge
from .dialogue import MultiTurnAnalyser
from .exploit_validator import ExploitValidator, ValidationResult
from .goal_planner import GoalPlanner, Goal, GoalType
from .corpus_generator import CorpusGenerator

__all__ = [
    "CorpusGenerator",
    "ExploitValidator",
    "FuzzingKnowledge",
    "FuzzingMemory",
    "FuzzingPlanner",
    "FuzzingState",
    "Goal",
    "GoalPlanner",
    "GoalType",
    "MultiTurnAnalyser",
    "ValidationResult",
]
