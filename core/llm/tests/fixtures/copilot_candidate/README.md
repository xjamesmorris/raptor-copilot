# Copilot candidate protocol fixtures

These files are independently authored synthetic examples for RAPTOR's
candidate-only Copilot event parser. They are not captured user transcripts,
not copied portions of the Copilot distribution, and not evidence that
`copilot --output-format json` emits this event stream.

Source facts were selected from
`dist/schemas/session-events.schema.json` in `@github/copilot` CLI
`1.0.84-4` (SHA-256
`ce6ea924e8bd3cb825046d7328a4b0922d787efa9868f9e7816df95e1ab2b545`).
The full schema and runtime distribution are intentionally not vendored.
`manifest.json` records fixture hashes and the evidence boundary so tests can
detect fixture drift without requiring a Copilot installation.

The parser's canonical UUID v4 requirement, immediate-predecessor `parentId`
chain, one root turn, one usage event per model call, and
receipt/idle/shutdown order are conservative candidate-profile assumptions.
They are not represented as facts proven from live `--output-format json`
output.

Candidate results expose evidence coverage without promoting it to
attestation:

- `identity_evidence=none`: no complete per-model-call runtime identity
  coverage. `session.start.selectedModel` and shutdown-only model fields do not
  raise this level.
- `identity_evidence=runtime`: every model call has a correlated
  `assistant.usage.model`.
- `identity_evidence=runtime_and_billing`: runtime coverage is complete and
  every call also reports billing identity through `copilotUsage.model` or
  fully model-labelled token details.
- `usage_evidence=none`: per-call usage coverage is missing or partial;
  shutdown aggregates alone never qualify.
- `usage_evidence=per_call`: every model call has one correlated
  `assistant.usage` event.
- `usage_evidence=per_call_and_shutdown`: per-call coverage is complete and
  shutdown `modelMetrics` covers every per-call model.

These levels record presence only. They do not prove served-model attestation,
billing correctness, token completeness, or reconciliation; W1b must apply
its own mandatory field and equality gates. Terminal/content success without
complete per-call runtime evidence is `candidate_complete_unevidenced` and is
available only on the parsed transcript for record-only inspection.
`admit_candidate_completion` refuses it.

`chunk_message_id_mode` is `n/a` for unchunked output and records `single`,
`distinct`, or `mixed` for chunk metadata. The current global replay rule
rejects reused `messageId` values, so accepted multi-chunk fixtures can report
`distinct` but do not prove that live Copilot uses distinct IDs. W2c/B2 must
capture the real mode before this profile is widened.

All identities, messages, model names, call IDs, usage numbers, and timestamps
are synthetic. The fixtures contain no credentials, private endpoints, or
actual user content.
