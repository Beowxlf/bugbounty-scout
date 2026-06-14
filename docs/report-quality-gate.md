# Report Quality Gate

`bbs evidence lint` and `bbs report lint` check evidence workspaces for missing
impact, assets, proof, reproduction steps, expected/actual behavior, severity
rationale, remediation, and scope notes. They also flag vague titles, possible
unredacted tokens/cookies/secrets/PII, and the need for manual validation.

Weak-language examples include “maybe,” “might,” “could be,” “I think,” “seems
like,” “probably,” and unsupported claims such as “should be critical.” Replace
these with bounded observations. Missing evidence includes a claim with no local
proof item or reproducible step. High/critical claims are warned when impact or
evidence is absent, or when the claim is only a missing header, public identifier,
or source-map exposure without demonstrated sensitive content.

Warnings are conservative review prompts, not verdicts. A warning does not mean
a report is invalid, and no absence of warnings proves correctness. Export is
never blocked. Researchers must manually confirm scope, redact output, establish
impact, and align severity with the program's policy.
