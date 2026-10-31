"""Guards against re-growing the removed autonomous decision surface.

The FuzzingPlanner/GoalPlanner decision loop (decide_next_action,
should_continue_fuzzing, select_fuzzing_strategy,
adapt_fuzzing_strategy, update_goal_progress,
should_continue_towards_goal) and CorpusGenerator.learn_from_crash
were removed: none had a production caller — the fuzz loop runs on
the operator's duration timer, and the SAGE AFL-flag prior is merged
at the raptor_fuzzing call site — and
``should_continue_towards_goal`` looped forever on
FIND_VULNERABILITY_TYPE goals (nothing ever set ``achieved``).

If a real decision loop lands, it must be WIRED into
raptor_fuzzing.py in the same change (and the goal-achievement check
must be able to complete); then delete this guard.
"""

from __future__ import annotations

from packages.autonomous.corpus_generator import CorpusGenerator
from packages.autonomous.goal_planner import GoalPlanner
from packages.autonomous.planner import FuzzingPlanner

_REMOVED_PLANNER = (
    "decide_next_action",
    "should_continue_fuzzing",
    "select_fuzzing_strategy",
)
_REMOVED_GOAL = (
    "adapt_fuzzing_strategy",
    "update_goal_progress",
    "should_continue_towards_goal",
)


def test_planner_decision_loop_stays_removed():
    for name in _REMOVED_PLANNER:
        assert not hasattr(FuzzingPlanner, name), (
            f"FuzzingPlanner.{name} re-grew without a production "
            "caller; wire it into raptor_fuzzing.py or keep it out"
        )


def test_goal_planner_stop_surface_stays_removed():
    for name in _REMOVED_GOAL:
        assert not hasattr(GoalPlanner, name), (
            f"GoalPlanner.{name} re-grew; the removed version could "
            "never complete FIND_VULNERABILITY_TYPE goals — wire a "
            "completable check into raptor_fuzzing.py or keep it out"
        )


def test_corpus_generator_learn_stub_stays_removed():
    assert not hasattr(CorpusGenerator, "learn_from_crash"), (
        "CorpusGenerator.learn_from_crash re-grew; it only "
        "logger.debug'd its result — store learned patterns through "
        "FuzzingMemory or keep it out"
    )


def test_decision_summary_keeps_report_shape():
    """raptor_fuzzing writes this block as ``planner_decisions``."""
    summary = FuzzingPlanner().get_decision_summary()
    assert summary == {"total_decisions": 0, "decisions": []}
