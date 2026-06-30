# Aegis-WAF Security Coverage Report

- Generated: 2026-06-30
- Rules directory: `D:/aa/waf/waf/rules`
- Corpus directory: `D:/aa/waf/waf/testdata/security-corpus`
- Rule files: 12
- SecRule count: 73
- Rule version: `custom`

## Gate Summary

| Metric | Result | Gate | Status |
| --- | ---: | ---: | --- |
| Attack block rate | 94.12% (32/34) | >= 90.00% | PASS |
| Benign false positives | 0/15 (0.00%) | <= 3 samples | PASS |

## Category Coverage

| Category | Attack Blocked | Attack Rate | Benign False Positives |
| --- | ---: | ---: | ---: |
| api | 2/3 | 66.67% | 0/2 |
| bot | 3/3 | 100.00% | 0/2 |
| protocol | 2/3 | 66.67% | 0/1 |
| rce | 4/4 | 100.00% | 0/1 |
| scanner | 4/4 | 100.00% | 0/1 |
| sqli | 4/4 | 100.00% | 0/2 |
| ssrf | 3/3 | 100.00% | 0/1 |
| traversal | 3/3 | 100.00% | 0/1 |
| upload | 2/2 | 100.00% | 0/1 |
| xss | 3/3 | 100.00% | 0/2 |
| xxe | 2/2 | 100.00% | 0/1 |

## Missed Attack Samples

- `api-graphql-introspection` (api): decision=observe score=4 rules=[910001]
- `protocol-trace-method` (protocol): decision=observe score=3 rules=[909005]

## False Positive Samples

No benign samples were blocked in this curated corpus.

## Notes

- This is a curated first-batch corpus for T149, not a claim of complete WAF coverage.
- The evaluator runs the repository rule files through the existing Coraza-backed detection path and `internal/pipeline`.
- Observe-only rule hits are not counted as blocked unless the final pipeline decision is `block`.
