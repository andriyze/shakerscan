# Hunter benchmark fixtures

Expected vulnerability **families** and **auth states** per local lab target, used by
`tests/benchmark/analyze_dast_benchmark.py` to produce a miss-analysis:

```
python3 tests/benchmark/analyze_dast_benchmark.py --profile crapi \
  --result <scan_report.json> --mode candidate --expected-json benchmarks/crapi/expected.json
```

These encode only *what classes of bug* a strong scan should confirm and *which principals*
should be exercised — never challenge names, routes, payloads, or scoreboard solutions. The scan
report itself now also carries a self `hunter_summary` (discovered/attempted/confirmed/blocked/
proof-gaps/next-campaigns) so miss-analysis is available without external fixtures.
