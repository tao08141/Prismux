#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

READY_PATTERN = "UDPlex started and ready"

SCENARIOS = [
    {"name": "Basic", "config_files": ["basic.yaml"]},
    {"name": "Auth Client-Server", "config_files": ["auth_server.yaml", "auth_client.yaml"]},
    {"name": "Filter", "config_files": ["filter_test.yaml"]},
    {"name": "Load Balancer", "config_files": ["load_balancer_test.yaml"]},
    {"name": "TCP Tunnel", "config_files": ["tcp_tunnel_server.yaml", "tcp_tunnel_client.yaml"]},
    {"name": "IP Router", "config_files": ["ip_router_test.yaml"]},
]


class TcpControlRelay:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        accept_timeout: float = 10.0,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.accept_timeout = accept_timeout
        self.error: str | None = None
        self._ready = threading.Event()
        self._done = threading.Event()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=2):
            raise RuntimeError("TCP control relay did not start in time")

    def join(self, timeout: float = 2.0) -> None:
        self._done.wait(timeout=timeout)

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except Exception:
                pass

    def _pipe(self, src: socket.socket, dst: socket.socket, stop: threading.Event) -> None:
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            stop.set()
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _run(self) -> None:
        try:
            self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener.bind((self.listen_host, self.listen_port))
            self._listener.listen(1)
            self._listener.settimeout(0.5)
            self._ready.set()

            started_at = time.time()
            client_conn = None
            while not self._stop.is_set():
                if (time.time() - started_at) > self.accept_timeout:
                    raise TimeoutError("tcp relay accept timeout")
                try:
                    client_conn, _ = self._listener.accept()
                    break
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        return
                    raise

            if client_conn is None:
                return
            with client_conn:
                target_conn = socket.create_connection(
                    (self.target_host, self.target_port), timeout=self.accept_timeout
                )
                with target_conn:
                    # Only accept/connect should be time-limited. Data relay must stay blocking,
                    # otherwise long tests (e.g. 60s) can break when the control channel is quiet.
                    client_conn.settimeout(None)
                    target_conn.settimeout(None)
                    stop = threading.Event()
                    t1 = threading.Thread(
                        target=self._pipe, args=(client_conn, target_conn, stop), daemon=True
                    )
                    t2 = threading.Thread(
                        target=self._pipe, args=(target_conn, client_conn, stop), daemon=True
                    )
                    t1.start()
                    t2.start()
                    t1.join()
                    t2.join()
        except Exception as exc:
            self.error = str(exc)
            self._ready.set()
        finally:
            if self._listener is not None:
                try:
                    self._listener.close()
                except Exception:
                    pass
                self._listener = None
            self._done.set()


def log(msg: str) -> None:
    print(msg, flush=True)


def check_command(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Command not found in PATH: {name}")


def resolve_project_root() -> Path:
    script_path = Path(__file__).resolve()
    project_root = script_path.parents[2]
    if not (project_root / "Cargo.toml").is_file():
        raise RuntimeError(f"Project root is invalid: {project_root}")
    return project_root


def resolve_prismux_binary(project_root: Path, prismux_bin: str | None) -> Path:
    if prismux_bin:
        binary = Path(prismux_bin).expanduser().resolve()
        if not binary.is_file():
            raise RuntimeError(f"Prismux binary not found: {binary}")
        return binary

    binary_name = "prismux.exe" if sys.platform.startswith("win") else "prismux"
    binary = project_root / "target" / "release" / binary_name
    if not binary.is_file():
        raise RuntimeError(
            f"Prismux binary not found: {binary}. Build first with `cargo build --release --bin prismux`."
        )
    return binary


def render_scenario_configs(
    project_root: Path,
    scenario_name: str,
    config_files: list[str],
    run_dir: Path,
    entry_port: int,
) -> list[Path]:
    examples_dir = project_root / "examples"
    rendered_paths: list[Path] = []
    scenario_id = scenario_name.replace(" ", "_").lower()

    for idx, config_file in enumerate(config_files, start=1):
        source = examples_dir / config_file
        if not source.is_file():
            raise RuntimeError(f"Config file not found: {source}")

        text = source.read_text(encoding="utf-8")
        text = text.replace("0.0.0.0:5202", f"0.0.0.0:{entry_port}")
        text = text.replace("127.0.0.1:5202", f"127.0.0.1:{entry_port}")

        target = run_dir / f"{scenario_id}_{idx}.{config_file}"
        target.write_text(text, encoding="utf-8", newline="\n")
        rendered_paths.append(target)

    return rendered_paths


def start_prismux_processes(
    prismux_binary: Path,
    project_root: Path,
    scenario_name: str,
    config_paths: list[Path],
    run_dir: Path,
) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []

    for idx, config_path in enumerate(config_paths, start=1):
        if not config_path.is_file():
            raise RuntimeError(f"Config file not found: {config_path}")

        out_path = run_dir / f"{scenario_name.replace(' ', '_').lower()}_{idx}.stdout.log"
        err_path = run_dir / f"{scenario_name.replace(' ', '_').lower()}_{idx}.stderr.log"
        out_f = out_path.open("w", encoding="utf-8", newline="\n")
        err_f = err_path.open("w", encoding="utf-8", newline="\n")

        proc = subprocess.Popen(
            [str(prismux_binary), "-c", str(config_path)],
            stdout=out_f,
            stderr=err_f,
            cwd=str(project_root),
            text=True,
        )
        processes.append(
            {
                "proc": proc,
                "stdout_file": out_f,
                "stderr_file": err_f,
                "stdout_path": out_path,
                "stderr_path": err_path,
                "config_path": config_path,
            }
        )

    return processes


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def wait_prismux_ready(processes: list[dict[str, Any]], timeout_sec: int) -> None:
    deadline = time.time() + timeout_sec
    ready = [False] * len(processes)

    while time.time() < deadline:
        for idx, item in enumerate(processes):
            proc: subprocess.Popen[str] = item["proc"]
            if ready[idx]:
                continue

            if proc.poll() is not None:
                logs = read_text(item["stdout_path"]) + "\n" + read_text(item["stderr_path"])
                raise RuntimeError(
                    f"Prismux exited early for {item['config_path']}\n--- Logs ---\n{logs}\n------------"
                )

            logs = read_text(item["stdout_path"]) + "\n" + read_text(item["stderr_path"])
            if READY_PATTERN in logs:
                ready[idx] = True
            elif "FATAL" in logs or "Failed " in logs or "Failed:" in logs:
                raise RuntimeError(
                    f"Prismux failed for {item['config_path']}\n--- Logs ---\n{logs}\n------------"
                )

        if all(ready):
            return
        time.sleep(0.2)

    pending = [
        str(item["config_path"])
        for idx, item in enumerate(processes)
        if idx < len(ready) and not ready[idx]
    ]
    raise RuntimeError(f"Timed out waiting for readiness: {', '.join(pending)}")


def stop_prismux_processes(processes: list[dict[str, Any]]) -> None:
    for item in processes:
        proc: subprocess.Popen[str] = item["proc"]
        if proc.poll() is None:
            proc.terminate()

    deadline = time.time() + 5
    for item in processes:
        proc: subprocess.Popen[str] = item["proc"]
        if proc.poll() is not None:
            continue
        remain = max(0.0, deadline - time.time())
        try:
            proc.wait(timeout=remain)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    for item in processes:
        try:
            item["stdout_file"].close()
        except Exception:
            pass
        try:
            item["stderr_file"].close()
        except Exception:
            pass


def run_iperf_case(
    iperf3_bin: str,
    direction: str,
    duration: int,
    bandwidth: str,
    length: int,
    max_loss_percent: float,
    entry_host: str,
    entry_port: int,
    server_host: str,
    server_port: int,
    run_dir: Path,
    scenario_name: str,
) -> dict[str, Any]:
    case_id = f"{scenario_name.replace(' ', '_').lower()}_{direction}"
    server_out = run_dir / f"{case_id}.iperf3.server.stdout.log"
    server_err = run_dir / f"{case_id}.iperf3.server.stderr.log"
    client_err = run_dir / f"{case_id}.iperf3.client.stderr.log"
    client_json_path = run_dir / f"{case_id}.iperf3.client.json"

    relay = TcpControlRelay(entry_host, entry_port, server_host, server_port)
    relay.start()

    with server_out.open("w", encoding="utf-8", newline="\n") as srv_out, server_err.open(
        "w", encoding="utf-8", newline="\n"
    ) as srv_err:
        server_proc = subprocess.Popen(
            [iperf3_bin, "-s", "-p", str(server_port), "-1", "-J"],
            stdout=srv_out,
            stderr=srv_err,
            text=True,
        )

        time.sleep(0.5)

        client_cmd = [
            iperf3_bin,
            "-u",
            "-J",
            "-c",
            entry_host,
            "-p",
            str(entry_port),
            "-t",
            str(duration),
            "-b",
            bandwidth,
            "-l",
            str(length),
        ]
        if direction == "download":
            client_cmd.append("-R")

        with client_err.open("w", encoding="utf-8", newline="\n") as cli_err:
            try:
                client_run = subprocess.run(
                    client_cmd,
                    stdout=subprocess.PIPE,
                    stderr=cli_err,
                    text=True,
                    timeout=duration + 30,
                )
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait(timeout=2)
                relay.stop()
                relay.join(timeout=1)
                timeout_err = "iperf3 client timeout"
                if relay.error:
                    timeout_err = f"{timeout_err}; relay={relay.error}"
                return {
                    "scenario": scenario_name,
                    "direction": direction,
                    "success": False,
                    "error": timeout_err,
                    "client_exit_code": None,
                    "mbps": None,
                    "lost_percent": None,
                    "jitter_ms": None,
                    "seconds": None,
                    "bytes": None,
                    "client_json_path": str(client_json_path),
                    "server_stdout_path": str(server_out),
                    "server_stderr_path": str(server_err),
                    "client_stderr_path": str(client_err),
                }

        client_stdout = client_run.stdout or ""
        client_json_path.write_text(client_stdout, encoding="utf-8", newline="\n")

        try:
            server_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait(timeout=2)

    relay.stop()
    relay.join(timeout=2)
    if relay.error:
        return {
            "scenario": scenario_name,
            "direction": direction,
            "success": False,
            "error": f"tcp relay failed: {relay.error}",
            "client_exit_code": client_run.returncode,
            "mbps": None,
            "lost_percent": None,
            "jitter_ms": None,
            "seconds": None,
            "bytes": None,
            "client_json_path": str(client_json_path),
            "server_stdout_path": str(server_out),
            "server_stderr_path": str(server_err),
            "client_stderr_path": str(client_err),
        }

    if client_run.returncode != 0:
        return {
            "scenario": scenario_name,
            "direction": direction,
            "success": False,
            "error": f"iperf3 client exited with {client_run.returncode}",
            "client_exit_code": client_run.returncode,
            "mbps": None,
            "lost_percent": None,
            "jitter_ms": None,
            "seconds": None,
            "bytes": None,
            "client_json_path": str(client_json_path),
            "server_stdout_path": str(server_out),
            "server_stderr_path": str(server_err),
            "client_stderr_path": str(client_err),
        }

    try:
        payload = json.loads(client_stdout)
    except json.JSONDecodeError as exc:
        return {
            "scenario": scenario_name,
            "direction": direction,
            "success": False,
            "error": f"failed to parse client json: {exc}",
            "client_exit_code": client_run.returncode,
            "mbps": None,
            "lost_percent": None,
            "jitter_ms": None,
            "seconds": None,
            "bytes": None,
            "client_json_path": str(client_json_path),
            "server_stdout_path": str(server_out),
            "server_stderr_path": str(server_err),
            "client_stderr_path": str(client_err),
        }

    end = payload.get("end", {})
    receiver = None
    for key in ("sum", "sum_received", "sum_sent"):
        item = end.get(key)
        if isinstance(item, dict) and "bits_per_second" in item:
            receiver = item
            if key != "sum_sent":
                break

    if not isinstance(receiver, dict):
        return {
            "scenario": scenario_name,
            "direction": direction,
            "success": False,
            "error": "missing throughput metrics in iperf3 output",
            "client_exit_code": client_run.returncode,
            "mbps": None,
            "lost_percent": None,
            "jitter_ms": None,
            "seconds": None,
            "bytes": None,
            "client_json_path": str(client_json_path),
            "server_stdout_path": str(server_out),
            "server_stderr_path": str(server_err),
            "client_stderr_path": str(client_err),
        }

    bits_per_second = receiver.get("bits_per_second")
    mbps = None if bits_per_second is None else float(bits_per_second) / 1_000_000
    lost_percent = receiver.get("lost_percent")
    if isinstance(lost_percent, (int, float)) and lost_percent > max_loss_percent:
        return {
            "scenario": scenario_name,
            "direction": direction,
            "success": False,
            "error": f"packet loss too high: {lost_percent:.2f}% > {max_loss_percent:.2f}%",
            "client_exit_code": client_run.returncode,
            "mbps": mbps,
            "lost_percent": lost_percent,
            "jitter_ms": receiver.get("jitter_ms"),
            "seconds": receiver.get("seconds"),
            "bytes": receiver.get("bytes"),
            "client_json_path": str(client_json_path),
            "server_stdout_path": str(server_out),
            "server_stderr_path": str(server_err),
            "client_stderr_path": str(client_err),
        }

    return {
        "scenario": scenario_name,
        "direction": direction,
        "success": True,
        "error": "",
        "client_exit_code": client_run.returncode,
        "mbps": mbps,
        "lost_percent": lost_percent,
        "jitter_ms": receiver.get("jitter_ms"),
        "seconds": receiver.get("seconds"),
        "bytes": receiver.get("bytes"),
        "client_json_path": str(client_json_path),
        "server_stdout_path": str(server_out),
        "server_stderr_path": str(server_err),
        "client_stderr_path": str(client_err),
    }


def write_results(output_dir: Path, results: list[dict[str, Any]]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "results.json"
    csv_path = output_dir / "results.csv"

    payload = {
        "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "results": results,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")

    fieldnames = [
        "scenario",
        "direction",
        "success",
        "mbps",
        "lost_percent",
        "jitter_ms",
        "seconds",
        "bytes",
        "client_exit_code",
        "error",
        "client_json_path",
        "server_stdout_path",
        "server_stderr_path",
        "client_stderr_path",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    return json_path, csv_path


def print_summary(results: list[dict[str, Any]]) -> None:
    log("")
    log("=== iperf3 UDP Stability Summary ===")
    for item in results:
        if item["success"]:
            mbps = f"{item['mbps']:.2f}" if isinstance(item["mbps"], (int, float)) else "n/a"
            loss = (
                f"{float(item['lost_percent']):.2f}%"
                if isinstance(item["lost_percent"], (int, float))
                else "n/a"
            )
            log(
                f"[PASS] {item['scenario']:<18} {item['direction']:<8} "
                f"throughput={mbps} Mbps loss={loss}"
            )
        else:
            log(f"[FAIL] {item['scenario']:<18} {item['direction']:<8} error={item['error']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run iperf3 UDP upload/download stability tests for udp_integration_rust scenarios."
    )
    parser.add_argument("--iperf3-bin", default="iperf3", help="iperf3 executable name/path")
    parser.add_argument("--prismux-bin", default=None, help="prismux executable path")
    parser.add_argument("--duration", type=int, default=60, help="test duration in seconds per direction")
    parser.add_argument("--bandwidth", default="100M", help="iperf3 UDP bandwidth, e.g. 50M/100M")
    parser.add_argument("--length", type=int, default=1024, help="iperf3 UDP payload length in bytes")
    parser.add_argument("--max-loss", type=float, default=5.0, help="max allowed packet loss percent")
    parser.add_argument("--entry-host", default="127.0.0.1", help="prismux entry host for iperf3 client")
    parser.add_argument(
        "--entry-port",
        type=int,
        default=25202,
        help="prismux entry port for iperf3 client (will rewrite scenario listen_addr from 5202)",
    )
    parser.add_argument("--server-host", default="127.0.0.1", help="iperf3 server host")
    parser.add_argument("--server-port", type=int, default=5201, help="iperf3 server port")
    parser.add_argument("--startup-timeout", type=int, default=30, help="prismux readiness timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = resolve_project_root()

    check_command(args.iperf3_bin)
    prismux_binary = resolve_prismux_binary(project_root, args.prismux_bin)

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_root = project_root / "metrics" / "iperf3"
    run_dir = output_root / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []

    for scenario in SCENARIOS:
        scenario_name = scenario["name"]
        config_files = scenario["config_files"]
        log(f"\n=== Scenario: {scenario_name} ===")
        processes: list[dict[str, Any]] = []

        try:
            config_paths = render_scenario_configs(
                project_root=project_root,
                scenario_name=scenario_name,
                config_files=config_files,
                run_dir=run_dir,
                entry_port=args.entry_port,
            )
            processes = start_prismux_processes(
                prismux_binary=prismux_binary,
                project_root=project_root,
                scenario_name=scenario_name,
                config_paths=config_paths,
                run_dir=run_dir,
            )
            wait_prismux_ready(processes, timeout_sec=args.startup_timeout)
            time.sleep(1)

            for direction in ("upload", "download"):
                log(f"Running {direction} for {scenario_name} ({args.duration}s)")
                result = run_iperf_case(
                    iperf3_bin=args.iperf3_bin,
                    direction=direction,
                    duration=args.duration,
                    bandwidth=args.bandwidth,
                    length=args.length,
                    max_loss_percent=args.max_loss,
                    entry_host=args.entry_host,
                    entry_port=args.entry_port,
                    server_host=args.server_host,
                    server_port=args.server_port,
                    run_dir=run_dir,
                    scenario_name=scenario_name,
                )
                results.append(result)

        except Exception as exc:
            err = str(exc)
            log(f"[ERROR] {scenario_name}: {err}")
            for direction in ("upload", "download"):
                results.append(
                    {
                        "scenario": scenario_name,
                        "direction": direction,
                        "success": False,
                        "mbps": None,
                        "lost_percent": None,
                        "jitter_ms": None,
                        "seconds": None,
                        "bytes": None,
                        "client_exit_code": None,
                        "error": err,
                        "client_json_path": "",
                        "server_stdout_path": "",
                        "server_stderr_path": "",
                        "client_stderr_path": "",
                    }
                )
        finally:
            stop_prismux_processes(processes)

    json_path, csv_path = write_results(run_dir, results)
    latest_json, latest_csv = write_results(output_root, results)

    print_summary(results)
    log("")
    log(f"Detailed artifacts: {run_dir}")
    log(f"Summary JSON: {json_path}")
    log(f"Summary CSV: {csv_path}")
    log(f"Latest JSON: {latest_json}")
    log(f"Latest CSV: {latest_csv}")

    failures = [item for item in results if not item["success"]]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
