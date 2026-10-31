#!/usr/bin/env python3
"""
Fuzzing Planner - Crash Prioritisation

Scores and orders crashes for analysis based on signal, input size,
and goal alignment. The fuzz loop itself runs on the operator's
duration timer (raptor_fuzzing.py); this module does not decide when
fuzzing starts or stops, and the SAGE cross-run AFL-flag prior is
merged by raptor_fuzzing directly (core.sage.hooks).
"""

from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger

logger = get_logger()


@dataclass
class FuzzingState:
    """Complete state of the fuzzing campaign, as passed to the
    crash prioritiser and the campaign report."""

    # Fuzzing metrics
    start_time: float
    total_execs: int = 0
    execs_per_sec: float = 0.0

    # Crash metrics
    total_crashes: int = 0
    unique_crashes: int = 0
    crashes_last_minute: int = 0
    exploitable_crashes: int = 0

    # Goal state
    target_goal: str | None = None

    # Binary characteristics
    binary_path: Path | None = None

    def is_finding_crashes(self) -> bool:
        """Check if we're actively finding crashes."""
        return self.crashes_last_minute > 0


class FuzzingPlanner:
    """Scores and orders crashes for analysis.

    Historic decision-loop methods (decide_next_action /
    should_continue_fuzzing / select_fuzzing_strategy) were removed:
    they had no production caller — the fuzz loop runs on the fixed
    duration timer and the SAGE AFL-flag prior is merged at the
    raptor_fuzzing call site — and keeping them advertised autonomy
    that did not exist. Wire a real decision loop into
    raptor_fuzzing.py before re-growing any of them.
    """

    def __init__(self) -> None:
        """Initialise the fuzzing planner."""
        logger.info("Fuzzing planner initialised")

    def recommend_crash_priority(self, crashes: list, state: FuzzingState) -> list:
        """
        Intelligently prioritise which crashes to analyse first.

        Instead of simple signal-based ranking, consider:
        - Which crashes are most likely exploitable
        - Which crashes give us new information
        - Which crashes match our goals

        Args:
            crashes: List of crashes to prioritise
            state: Current fuzzing state

        Returns:
            Prioritised list of crashes
        """
        logger.info("Autonomously prioritising crashes for analysis...")

        # Score each crash based on multiple factors
        crash_scores = []

        for crash in crashes:
            score = 0.0
            factors = []

            # Factor 1: Signal priority (baseline)
            signal_scores = {
                "11": 10.0,  # SIGSEGV - memory corruption
                "06": 8.0,   # SIGABRT - heap issues
                "04": 6.0,   # SIGILL - code execution
                "08": 4.0,   # SIGFPE - arithmetic
            }
            signal_score = signal_scores.get(crash.signal, 2.0)
            score += signal_score
            factors.append(f"signal:{signal_score:.1f}")

            # Factor 2: Input size (smaller = easier to exploit)
            if crash.size < 100:
                score += 5.0
                factors.append("small_input:5.0")
            elif crash.size < 1000:
                score += 2.0
                factors.append("medium_input:2.0")

            # Factor 3: Goal alignment (if we have a target)
            if state.target_goal:
                if "parser" in state.target_goal.lower() and "parse" in str(crash.input_file):
                    score += 10.0
                    factors.append("goal_match:10.0")

            # Store score
            crash_scores.append((crash, score, factors))

        # Sort by score (highest first)
        crash_scores.sort(key=lambda x: x[1], reverse=True)

        # Log prioritisation
        logger.info("Crash prioritisation (top 5):")
        for i, (crash, score, factors) in enumerate(crash_scores[:5], 1):
            logger.info("  %s. %s - Score: %.1f - Factors: %s", i, crash.crash_id, score, ', '.join(factors))

        # Return prioritised list
        return [c for c, s, f in crash_scores]

    def get_decision_summary(self) -> dict:
        """Return the decision-summary report block.

        Kept for report-shape compatibility (raptor_fuzzing writes it
        as ``planner_decisions``). No decision loop exists, so the
        block is always empty — exactly what production runs recorded
        when the removed decision methods still existed uncalled.
        """
        return {
            "total_decisions": 0,
            "decisions": [],
        }
