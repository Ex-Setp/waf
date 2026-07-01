# Aegis-WAF Security Coverage Report

- Generated: 2026-06-30
- Rules directory: `D:/aa/waf/waf/rules`
- Corpus directory: `D:/aa/waf/waf/testdata/security-corpus`
- Rule files: 12
- SecRule count: 572
- Rule version: `custom`

## Gate Summary

| Metric | Result | Gate | Status |
| --- | ---: | ---: | --- |
| Attack block rate | 95.89% (70/73) | >= 90.00% | PASS |
| Benign false positives | 0/67 (0.00%) | <= 3 samples | PASS |

## Category Coverage

| Category | Attack Blocked | Attack Rate | Benign False Positives |
| --- | ---: | ---: | ---: |
| api | 6/8 | 75.00% | 0/20 |
| bot | 9/9 | 100.00% | 0/5 |
| protocol | 7/7 | 100.00% | 0/6 |
| rce | 8/9 | 88.89% | 0/1 |
| scanner | 12/12 | 100.00% | 0/8 |
| sqli | 10/10 | 100.00% | 0/4 |
| ssrf | 3/3 | 100.00% | 0/3 |
| traversal | 3/3 | 100.00% | 0/5 |
| upload | 2/2 | 100.00% | 0/6 |
| xss | 8/8 | 100.00% | 0/5 |
| xxe | 2/2 | 100.00% | 0/4 |

## Missed Attack Samples

- `api-idor-user-id` (api): decision=allow score=0 rules=[]
- `api-jwt-none-body` (api): decision=allow score=1 rules=[910062]
- `rce-ognl-struts2` (rce): decision=allow score=0 rules=[]

## False Positive Samples

No benign samples were blocked in this curated corpus.

## Notes

- This is a curated first-batch corpus for T149, not a claim of complete WAF coverage.
- The evaluator runs the repository rule files through the existing Coraza-backed detection path and `internal/pipeline`.
- Observe-only rule hits are not counted as blocked unless the final pipeline decision is `block`.
