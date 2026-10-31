#!/usr/bin/env python3
"""
Goal-Directed Planning - Goal Parsing and Crash Re-ranking

Parses user-specified goals ("find heap overflow vulnerabilities",
"target parser code", "achieve remote code execution") into
structured Goal objects, and re-ranks crashes by goal alignment.
Goals steer prioritisation only — the fuzz loop's duration and stop
conditions are the operator's timer, not goal state.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.logging import get_logger

logger = get_logger()


class GoalType(Enum):
    """Types of goals the system can pursue. Feel free to add to these as you see fit."""
    FIND_VULNERABILITY_TYPE = "find_vulnerability_type"  # e.g., "heap overflow"
    TARGET_CODE_AREA = "target_code_area"  # e.g., "parser"
    ACHIEVE_EXPLOIT_TYPE = "achieve_exploit_type"  # e.g., "RCE"
    MAXIMIZE_COVERAGE = "maximize_coverage"  # General exploration
    FIND_ANY_CRASH = "find_any_crash"  # Fast crash finding


@dataclass
class Goal:
    """A high-level goal to achieve."""
    goal_type: GoalType
    description: str  # Human-readable description
    target_value: str | None = None  # Target value (e.g., "heap_overflow")

    # Progress tracking
    progress: float = 0.0  # 0.0 to 1.0
    achieved: bool = False
    start_time: float = field(default_factory=time.time)

    # Strategy adjustments for this goal
    strategy_hints: dict[str, Any] = field(default_factory=dict)


class GoalPlanner:
    """Parses operator goals and re-ranks crashes against them.

    Historic goal-progress methods (adapt_fuzzing_strategy /
    update_goal_progress / should_continue_towards_goal) were removed:
    they had no production caller, and should_continue_towards_goal
    looped forever on FIND_VULNERABILITY_TYPE goals — no code path
    ever set ``achieved`` for that goal type. Any future stop-
    condition wiring must close that loop (verify the crash type
    actually matches) before consulting goal state.
    """

    def __init__(self) -> None:
        """Initialize goal planner."""
        self.current_goal: Goal | None = None
        self.goal_history: list[Goal] = []
        logger.info("Goal-directed planner initialized")

    def set_goal(self, goal: Goal) -> None:
        """
        Set a new goal to work towards.

        Args:
            goal: Goal to achieve
        """
        if self.current_goal:
            if not self.current_goal.achieved:
                logger.info("Replacing current goal: %s", self.current_goal.description)
            self.goal_history.append(self.current_goal)

        self.current_goal = goal
        logger.info("=" * 70)
        logger.info("NEW GOAL SET")
        logger.info("=" * 70)
        logger.info("Goal: %s", goal.description)
        logger.info("Type: %s", goal.goal_type.value)
        if goal.target_value:
            logger.info("Target: %s", goal.target_value)

    def create_goal_from_user_input(self, user_goal: str) -> Goal:
        """
        Parse user input and create a structured goal.

        Args:
            user_goal: User's goal description

        Returns:
            Structured Goal object
        """
        user_goal_lower = user_goal.lower()

        # Detect goal type from user input
        if any(vuln in user_goal_lower for vuln in [
            "heap overflow", "stack overflow", "use-after-free",
            "buffer overflow", "null pointer", "uaf"
        ]):
            # Extract vulnerability type
            if "heap overflow" in user_goal_lower:
                target = "heap_overflow"
            elif "stack overflow" in user_goal_lower:
                target = "stack_overflow"
            elif "use-after-free" in user_goal_lower or "uaf" in user_goal_lower:
                target = "use_after_free"
            elif "buffer overflow" in user_goal_lower:
                target = "buffer_overflow"
            else:
                target = "memory_corruption"

            return Goal(
                goal_type=GoalType.FIND_VULNERABILITY_TYPE,
                description=user_goal,
                target_value=target,
                strategy_hints={
                    "focus_on_memory": True,
                    "enable_asan": True,
                    "mutation_strategy": "aggressive",
                }
            )

        if any(code_area in user_goal_lower for code_area in [
            "parser", "network", "authentication", "crypto"
        ]):
            # Target specific code area
            if "parser" in user_goal_lower:
                target = "parser"
            elif "network" in user_goal_lower:
                target = "network"
            elif "auth" in user_goal_lower:
                target = "authentication"
            elif "crypto" in user_goal_lower:
                target = "cryptography"
            else:
                target = "unknown"

            return Goal(
                goal_type=GoalType.TARGET_CODE_AREA,
                description=user_goal,
                target_value=target,
                strategy_hints={
                    "input_format": target,
                    "mutation_strategy": "structured",
                }
            )

        if any(exploit in user_goal_lower for exploit in [
            "rce", "code execution", "shell", "exploit"
        ]):
            return Goal(
                goal_type=GoalType.ACHIEVE_EXPLOIT_TYPE,
                description=user_goal,
                target_value="rce",
                strategy_hints={
                    "prioritize_exploitable": True,
                    "deep_analysis": True,
                }
            )

        if "coverage" in user_goal_lower or "explore" in user_goal_lower:
            return Goal(
                goal_type=GoalType.MAXIMIZE_COVERAGE,
                description=user_goal,
                strategy_hints={
                    "mutation_strategy": "diverse",
                    "parallel_instances": 4,
                }
            )

        # Default: find any crash
        return Goal(
            goal_type=GoalType.FIND_ANY_CRASH,
            description=user_goal,
            strategy_hints={
                "fast_mode": True,
            }
        )

    def prioritize_crashes_for_goal(self, crashes: list) -> list:
        """
        Prioritize crashes based on current goal.

        Args:
            crashes: List of crashes

        Returns:
            Reprioritized list
        """
        if not self.current_goal:
            return crashes

        goal = self.current_goal

        # Re-score crashes based on goal alignment
        scored_crashes = []

        for crash in crashes:
            base_score = getattr(crash, 'score', 1.0)
            goal_bonus = 0.0

            # Goal-specific bonuses
            if goal.goal_type == GoalType.FIND_VULNERABILITY_TYPE:
                # Check if crash type matches goal
                crash_type = getattr(crash, 'crash_type', 'unknown')
                if goal.target_value and goal.target_value in crash_type:
                    goal_bonus = 100.0  # Huge bonus for exact match
                    logger.info("✨ Crash %s matches goal: %s", crash.crash_id, goal.target_value)

            elif goal.goal_type == GoalType.TARGET_CODE_AREA:
                # Check if crash is in target code area
                function_name = getattr(crash, 'function_name', '')
                if goal.target_value and goal.target_value in function_name.lower():
                    goal_bonus = 50.0
                    logger.info("✨ Crash %s in target area: %s", crash.crash_id, goal.target_value)

            elif goal.goal_type == GoalType.ACHIEVE_EXPLOIT_TYPE:
                # Prioritize highly exploitable crashes
                if getattr(crash, 'exploitability', 'unknown') == 'exploitable':
                    goal_bonus = 75.0

            final_score = base_score + goal_bonus
            scored_crashes.append((crash, final_score))

        # Sort by final score
        scored_crashes.sort(key=lambda x: x[1], reverse=True)

        return [c for c, s in scored_crashes]

    def get_summary(self) -> dict:
        """Get summary of goals and progress.

        ``progress`` / ``achieved`` are static defaults today: no
        production path advances them (the progress updater was
        removed as dead code). The keys stay for report-shape
        compatibility.
        """
        return {
            "current_goal": {
                "description": self.current_goal.description,
                "type": self.current_goal.goal_type.value,
                "progress": self.current_goal.progress,
                "achieved": self.current_goal.achieved,
            } if self.current_goal else None,
            "total_goals_attempted": len(self.goal_history) + (1 if self.current_goal else 0),
            "goals_achieved": sum(1 for g in self.goal_history if g.achieved) + (
                1 if self.current_goal and self.current_goal.achieved else 0
            ),
        }
