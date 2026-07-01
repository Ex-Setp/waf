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
| Attack block rate delta vs baseline | +0.00% | >= -0.00% | PASS |
| Benign false positive delta vs baseline | +0 | <= +0 samples | PASS |
| Overall gate | PASS | regression + absolute thresholds | PASS |

## Baseline Comparison

| Metric | Baseline | Current | Delta |
| --- | ---: | ---: | ---: |
| Attack block rate | 95.89% | 95.89% | +0.00% |
| Benign false positives | 0 | 0 | +0 |
| Rule count | 572 | 572 | +0 |
| Rule version | `custom` | `custom` | unchanged |

## Category Coverage

| Category | Attack Blocked | Attack Rate | Delta | Benign False Positives | Delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| api | 6/8 | 75.00% | +0.00% | 0/20 | +0 |
| bot | 9/9 | 100.00% | +0.00% | 0/5 | +0 |
| protocol | 7/7 | 100.00% | +0.00% | 0/6 | +0 |
| rce | 8/9 | 88.89% | +0.00% | 0/1 | +0 |
| scanner | 12/12 | 100.00% | +0.00% | 0/8 | +0 |
| sqli | 10/10 | 100.00% | +0.00% | 0/4 | +0 |
| ssrf | 3/3 | 100.00% | +0.00% | 0/3 | +0 |
| traversal | 3/3 | 100.00% | +0.00% | 0/5 | +0 |
| upload | 2/2 | 100.00% | +0.00% | 0/6 | +0 |
| xss | 8/8 | 100.00% | +0.00% | 0/5 | +0 |
| xxe | 2/2 | 100.00% | +0.00% | 0/4 | +0 |

## Top Missed Attack Samples

- `api-idor-user-id` (api): decision=allow score=0 rules=[]
- `api-jwt-none-body` (api): decision=allow score=1 rules=[910062]
- `rce-ognl-struts2` (rce): decision=allow score=0 rules=[]

## Top False Positives

No benign samples were blocked in this curated corpus.

## Gate Failures

- None.

## Notes

- This is a curated first-batch corpus for T149, not a claim of complete WAF coverage.
- The evaluator runs the repository rule files through the existing Coraza-backed detection path and `internal/pipeline`.
- A baseline comparison is shown only when a baseline JSON is provided.
- Observe-only rule hits are not counted as blocked unless the final pipeline decision is `block`.
