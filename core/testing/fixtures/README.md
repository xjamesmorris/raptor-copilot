# Shared frontend fixtures

`core.testing.host_events` provides immutable builders for the existing
Claude hook shapes and candidate-only Copilot hook shapes. Every call returns
fresh payload containers so malformed, duplicate, reordered, stale, and
foreign-session cases cannot mutate another test. Candidate records always
carry `candidate-unverified`; they do not grant ownership, lifecycle effects,
coverage attribution, or live validation.

`core.testing.feature_ledger` derives command, skill, and agent rows from the
current `.claude` source tree. It reuses the repository's command-frontmatter
parser and accepts externally discovered host builtins as explicit inputs.
Command/skill/builtin namespace collisions remain separate ledger rows and
are reported rather than silently deduplicated.

The fixtures are test infrastructure. Production host adapters select their
own trusted profile and effect registration; fixture fields cannot select or
enable either.
