# Contributing

Changes must preserve portability, deny-by-default containment, controller-pull evidence flow, per-run destruction of REMnux and the sandbox, and the rule that sample-derived text is untrusted data.

Before submitting a change, run:

```bash
python -m pytest
ruff check controller tests
```

Do not add third-party binaries, sample files, evidence, credentials, local paths, operator identities, or deployment addresses. Pin every external input by version and URL in `versions.lock.yml`.
