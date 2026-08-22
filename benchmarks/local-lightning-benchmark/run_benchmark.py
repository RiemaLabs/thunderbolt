#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parent
COMPOSE = ROOT / "docker-compose.yml"
PROJECT = "thunderbolt-ln-bench"
BTC_RPC = ["bitcoin-cli", "-regtest", "-rpcuser=rpcuser", "-rpcpassword=rpcpass"]
LN_RPC = ["lightning-cli", "--network=regtest"]


def log(message: str):
    print(f"[lightning-bench] {message}", file=sys.stderr, flush=True)


def run(cmd, *, cwd=None, capture=True, check=True):
    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=capture,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def dc(*args, capture=True, check=True):
    return run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args], capture=capture, check=check)


def dc_exec(service, *args, capture=True, check=True):
    return dc("exec", "-T", service, *args, capture=capture, check=check)


def btc(*args, wallet: Optional[str] = None):
    cmd = BTC_RPC.copy()
    if wallet is not None:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(args)
    return dc_exec("bitcoind", *cmd).stdout.strip()


def btc_json(*args, wallet: Optional[str] = None):
    return json.loads(btc(*args, wallet=wallet))


def ln(service, *args):
    return dc_exec(service, *LN_RPC, *args).stdout.strip()


def ln_json(service, *args):
    return json.loads(ln(service, *args))


def wait_until(predicate: Callable[[], bool], *, timeout: float, interval: float = 1.0, label: str = "condition"):
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        time.sleep(interval)
    if last_exc is not None:
        raise RuntimeError(f"timed out waiting for {label}: {last_exc}")
    raise RuntimeError(f"timed out waiting for {label}")


@dataclass
class StageSummary:
    total_secs: float
    average_secs: float
    min_secs: float
    max_secs: float


@dataclass
class LightningLocalBenchmarkReport:
    iterations: int
    bootstrap_secs: float
    invoice_create: StageSummary
    payment_settle: StageSummary
    total_payment: StageSummary


class Acc:
    def __init__(self):
        self.values = []

    def record(self, value: float):
        self.values.append(value)

    def finish(self) -> StageSummary:
        return StageSummary(
            total_secs=sum(self.values),
            average_secs=sum(self.values) / len(self.values),
            min_secs=min(self.values),
            max_secs=max(self.values),
        )


def bootstrap(channel_amount_sat: int):
    log("resetting docker compose stack")
    dc("down", "-v", "--remove-orphans", capture=True, check=False)
    log("starting docker compose stack")
    dc("up", "-d", capture=True, check=True)

    wait_until(
        lambda: "chain" in btc_json("getblockchaininfo"),
        timeout=120,
        label="bitcoind readiness",
    )
    log("creating regtest wallet")
    btc("createwallet", "bench")
    mining_addr = btc("getnewaddress", wallet="bench")
    log("mining 150 blocks for mature coins")
    btc("generatetoaddress", "150", mining_addr, wallet="bench")

    wait_until(
        lambda: ln_json("cln1", "getinfo").get("id") is not None,
        timeout=120,
        label="cln1 readiness",
    )
    wait_until(
        lambda: ln_json("cln2", "getinfo").get("id") is not None,
        timeout=120,
        label="cln2 readiness",
    )

    log("requesting CLN1 funding address")
    cln1_addr = ln_json("cln1", "newaddr", "bech32")["bech32"]
    log("funding CLN1 on-chain wallet")
    btc("sendtoaddress", cln1_addr, "1", wallet="bench")
    log("mining 6 blocks to confirm CLN1 funding")
    btc("generatetoaddress", "6", mining_addr, wallet="bench")

    wait_until(
        lambda: len(ln_json("cln1", "listfunds").get("outputs", [])) > 0,
        timeout=120,
        label="cln1 wallet funding",
    )

    log("connecting CLN1 to CLN2")
    cln2_info = ln_json("cln2", "getinfo")
    peer_id = cln2_info["id"]
    ln_json("cln1", "connect", peer_id, "cln2", "9735")
    log("opening channel from CLN1 to CLN2")
    ln_json("cln1", "fundchannel", peer_id, str(channel_amount_sat))

    wait_until(
        lambda: len(ln_json("cln1", "listfunds").get("channels", [])) > 0,
        timeout=120,
        label="channel funding broadcast",
    )
    log("mining 8 blocks to confirm channel")
    btc("generatetoaddress", "8", mining_addr, wallet="bench")

    def channel_ready():
        channels = ln_json("cln1", "listpeerchannels", peer_id).get("channels", [])
        return any(channel.get("state") == "CHANNELD_NORMAL" for channel in channels)

    wait_until(channel_ready, timeout=180, label="channel ready")
    log("channel is ready; starting payment iterations")


def run_benchmark(iterations: int, amount_msat: int, channel_amount_sat: int) -> LightningLocalBenchmarkReport:
    invoice_acc = Acc()
    pay_acc = Acc()
    total_acc = Acc()

    bootstrap_start = time.perf_counter()
    bootstrap(channel_amount_sat)
    bootstrap_secs = time.perf_counter() - bootstrap_start

    for i in range(iterations):
        label = f"bench-{i}-{uuid.uuid4().hex}"
        total_start = time.perf_counter()

        invoice_start = time.perf_counter()
        invoice = ln_json("cln2", "invoice", f"{amount_msat}msat", label, label)
        invoice_acc.record(time.perf_counter() - invoice_start)

        pay_start = time.perf_counter()
        payment = ln_json("cln1", "pay", invoice["bolt11"])
        if payment.get("status") != "complete":
            raise RuntimeError(f"payment did not complete: {payment}")
        pay_acc.record(time.perf_counter() - pay_start)

        total_acc.record(time.perf_counter() - total_start)

    return LightningLocalBenchmarkReport(
        iterations=iterations,
        bootstrap_secs=bootstrap_secs,
        invoice_create=invoice_acc.finish(),
        payment_settle=pay_acc.finish(),
        total_payment=total_acc.finish(),
    )


def print_report(report: LightningLocalBenchmarkReport):
    print("local lightning regtest benchmark")
    print(f"iterations: {report.iterations}")
    print(f"bootstrap_secs: {report.bootstrap_secs:.3f}")
    print("stage                 avg (ms)   min (ms)   max (ms)   total (ms)")
    print("---------------------------------------------------------------")
    for label, summary in [
        ("invoice_create", report.invoice_create),
        ("payment_settle", report.payment_settle),
        ("total_payment", report.total_payment),
    ]:
        print(
            f"{label:20} {summary.average_secs * 1e3:>9.3f} {summary.min_secs * 1e3:>10.3f} {summary.max_secs * 1e3:>10.3f} {summary.total_secs * 1e3:>11.3f}"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--amount-msat", type=int, default=10_000)
    parser.add_argument("--channel-amount-sat", type=int, default=500_000)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()

    try:
        report = run_benchmark(args.iterations, args.amount_msat, args.channel_amount_sat)
        if args.json:
            print(json.dumps(asdict(report), indent=2))
        else:
            print_report(report)
    finally:
        if not args.keep_running:
            dc("down", "-v", "--remove-orphans", capture=True, check=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"benchmark failed: {exc}", file=sys.stderr)
        sys.exit(1)
