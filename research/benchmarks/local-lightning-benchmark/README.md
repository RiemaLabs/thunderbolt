# Local Lightning regtest benchmark

This benchmark starts a local regtest stack using Docker Compose:
- 1 `bitcoind` node
- 2 Core Lightning nodes (`cln1`, `cln2`)

It measures:
- invoice creation latency on `cln2`
- payment settlement latency on `cln1`
- total payment latency (`invoice + pay`)

## Run

```bash
python3 research/benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10
```

JSON output:

```bash
python3 research/benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10 --json
```

Keep containers alive after the run for inspection:

```bash
python3 research/benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 1 --keep-running
```
