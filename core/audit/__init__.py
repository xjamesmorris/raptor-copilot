"""Hypothesis-driven, tool-grounded security review of coverage gaps.

Core flow (a small slice of the package — see docs/audit.md for the
full pipeline): ``gaps`` computes what to review from inventory +
coverage records, ``context`` assembles the per-function slice,
``strategy`` picks review strategies, ``record`` tracks source hashes
and the audit log, and ``report``/``findings`` emit the results.
"""
