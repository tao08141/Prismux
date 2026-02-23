use chrono::Utc;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LISTEN_PORT: u16 = 5201;
const SEND_PORT: u16 = 5202;
const TEST_DURATION: Duration = Duration::from_secs(10);
const MAX_PACKET_LOSS: f64 = 0.05;
const PACKET_SIZE: usize = 1072;
const PAYLOAD_SIZE: usize = 1024;
const LATENCY_SAMPLE_CAP: usize = 20_000;

struct TestConfig {
    name: &'static str,
    config_files: &'static [&'static str],
    test_port: u16,
    target_port: u16,
    duration: Duration,
}

#[derive(Clone, Debug)]
struct TestResult {
    config_name: String,
    sent: i64,
    received: i64,
    error_packets: i64,
    loss_rate: f64,
    throughput: f64,
    bytes_received: i64,
    mbps: f64,
    total_mbytes: f64,
    packet_size_bytes: usize,
    avg_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    min_latency_ms: f64,
    max_latency_ms: f64,
    success: bool,
    error: String,
}

impl TestResult {
    fn new(config_name: String) -> Self {
        Self {
            config_name,
            sent: 0,
            received: 0,
            error_packets: 0,
            loss_rate: 0.0,
            throughput: 0.0,
            bytes_received: 0,
            mbps: 0.0,
            total_mbytes: 0.0,
            packet_size_bytes: PACKET_SIZE,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            min_latency_ms: 0.0,
            max_latency_ms: 0.0,
            success: false,
            error: String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct LatencySummary {
    avg_ns: f64,
    p50_ns: f64,
    p95_ns: f64,
    p99_ns: f64,
    min_ns: i64,
    max_ns: i64,
}

#[derive(Serialize)]
struct MetricsFile {
    repo: String,
    branch: String,
    sha: String,
    run_id: String,
    runner_os: String,
    timestamp: String,
    duration_sec: f64,
    results: Vec<MetricEntry>,
}

#[derive(Serialize)]
struct MetricEntry {
    name: String,
    sent: i64,
    received: i64,
    error_packets: i64,
    loss_rate: f64,
    throughput_pps: f64,
    mbps: f64,
    total_mbytes: f64,
    packet_size_bytes: usize,
    avg_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    p99_latency_ms: f64,
    min_latency_ms: f64,
    max_latency_ms: f64,
    success: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

enum ProcessEvent {
    Ready,
    Failed(String),
}

#[derive(Default)]
struct Bitset {
    words: Vec<u64>,
}

impl Bitset {
    fn test(&self, bit: u32) -> bool {
        let idx = (bit / 64) as usize;
        if idx >= self.words.len() {
            return false;
        }
        (self.words[idx] & (1u64 << (bit % 64))) != 0
    }

    fn set(&mut self, bit: u32) {
        let idx = (bit / 64) as usize;
        if idx >= self.words.len() {
            self.words.resize(idx + 1, 0);
        }
        self.words[idx] |= 1u64 << (bit % 64);
    }
}

#[derive(Default)]
struct LatencyAccumulator {
    count: i64,
    sum_ns: i128,
    min_ns: i64,
    max_ns: i64,
    sample: Vec<i64>,
}

impl LatencyAccumulator {
    fn observe(&mut self, value_ns: i64) {
        if self.count == 0 {
            self.min_ns = value_ns;
            self.max_ns = value_ns;
        } else {
            self.min_ns = self.min_ns.min(value_ns);
            self.max_ns = self.max_ns.max(value_ns);
        }
        self.count += 1;
        self.sum_ns += value_ns as i128;
        if self.sample.len() < LATENCY_SAMPLE_CAP {
            self.sample.push(value_ns);
        }
    }

    fn finalize(mut self) -> LatencySummary {
        if self.count == 0 {
            return LatencySummary::default();
        }

        self.sample.sort_unstable();
        let percentile = |p: f64, sample: &[i64]| -> f64 {
            if sample.is_empty() {
                return 0.0;
            }
            let raw = p * (sample.len() as f64 - 1.0) + 0.5;
            let mut rank = raw.floor() as isize;
            if rank < 0 {
                rank = 0;
            }
            if rank as usize >= sample.len() {
                rank = sample.len() as isize - 1;
            }
            sample[rank as usize] as f64
        };

        LatencySummary {
            avg_ns: (self.sum_ns as f64) / self.count as f64,
            p50_ns: percentile(0.50, &self.sample),
            p95_ns: percentile(0.95, &self.sample),
            p99_ns: percentile(0.99, &self.sample),
            min_ns: self.min_ns,
            max_ns: self.max_ns,
        }
    }
}

#[test]
#[ignore = "Generates throughput metrics and takes a few minutes; run explicitly."]
fn udp_integration_metrics() {
    if let Err(err) = run_suite() {
        panic!("{err}");
    }
}

fn run_suite() -> Result<(), String> {
    let project_root = get_project_root()?;
    let examples_dir = project_root.join("examples");
    let prismux_binary = resolve_prismux_binary(&project_root)?;
    let test_configs = test_configs();

    println!("Using Prismux binary: {}", prismux_binary.display());

    let mut results = Vec::with_capacity(test_configs.len() * 2);
    for config in &test_configs {
        println!("\n=== {} - Packet Loss Test ===", config.name);
        let loss_result = run_test(
            &prismux_binary,
            &examples_dir,
            config,
            "Packet Loss Test",
            true,
        );
        if loss_result.success {
            println!("{} - Packet Loss Test: PASSED", config.name);
        } else {
            println!(
                "{} - Packet Loss Test: FAILED - {}",
                config.name, loss_result.error
            );
        }
        results.push(loss_result);

        println!("\n=== {} - Performance Test ===", config.name);
        let perf_result = run_test(
            &prismux_binary,
            &examples_dir,
            config,
            "Performance Test",
            false,
        );
        if perf_result.success {
            println!("{} - Performance Test: PASSED", config.name);
        } else {
            println!(
                "{} - Performance Test: FAILED - {}",
                config.name, perf_result.error
            );
        }
        results.push(perf_result);
    }

    println!("\n=== Test Summary ===");
    let mut passed = 0usize;
    for result in &results {
        let status = if result.success {
            passed += 1;
            "PASS"
        } else {
            "FAIL"
        };
        println!(
            "{:<28} | Sent: {:>7} | Received: {:>7} | Err: {:>5} | Loss: {:>6.2}% | Thr: {:>9.0} pps | Rate: {:>7.2} Mbits/s | Total: {:>7.2} MB | Lat(ms) avg/p50/p95/p99 min-max: {:.2}/{:.2}/{:.2}/{:.2} {:.2}-{:.2} | Status: {}",
            result.config_name,
            result.sent,
            result.received,
            result.error_packets,
            result.loss_rate * 100.0,
            result.throughput,
            result.mbps,
            result.total_mbytes,
            result.avg_latency_ms,
            result.p50_latency_ms,
            result.p95_latency_ms,
            result.p99_latency_ms,
            result.min_latency_ms,
            result.max_latency_ms,
            status
        );
    }

    println!("\nTotal: {passed}/{} tests passed", results.len());

    if let Err(err) = write_json_metrics(&project_root, &results, TEST_DURATION) {
        eprintln!("Failed to write metrics JSON: {err}");
    }

    if passed != results.len() {
        return Err(format!("{} test(s) failed", results.len() - passed));
    }

    Ok(())
}

fn test_configs() -> Vec<TestConfig> {
    vec![
        TestConfig {
            name: "Basic",
            config_files: &["basic.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
        TestConfig {
            name: "Auth Client-Server",
            config_files: &["auth_server.yaml", "auth_client.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
        TestConfig {
            name: "Filter",
            config_files: &["filter_test.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
        TestConfig {
            name: "Load Balancer",
            config_files: &["load_balancer_test.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
        TestConfig {
            name: "TCP Tunnel",
            config_files: &["tcp_tunnel_server.yaml", "tcp_tunnel_client.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
        TestConfig {
            name: "IP Router",
            config_files: &["ip_router_test.yaml"],
            test_port: LISTEN_PORT,
            target_port: SEND_PORT,
            duration: TEST_DURATION,
        },
    ]
}

fn run_test(
    prismux_binary: &Path,
    examples_dir: &Path,
    config: &TestConfig,
    label: &str,
    with_sleep: bool,
) -> TestResult {
    let mut result = TestResult::new(format!("{} {}", config.name, label));
    let mut processes = Vec::new();

    for config_file in config.config_files {
        let config_path = examples_dir.join(config_file);
        if !config_path.is_file() {
            result.error = format!("Config file not found: {}", config_path.display());
            return result;
        }
        match start_prismux_process(prismux_binary, &config_path) {
            Ok(child) => processes.push(child),
            Err(err) => {
                cleanup_processes(&mut processes);
                result.error = err;
                return result;
            }
        }
    }

    thread::sleep(Duration::from_secs(2));

    if let Ok(sock) = UdpSocket::bind("127.0.0.1:0") {
        if sock.connect(("127.0.0.1", config.target_port)).is_ok() {
            println!(
                "Debug: Successfully connected to port {}",
                config.target_port
            );
        } else {
            eprintln!(
                "Warning: Cannot connect to target port {}",
                config.target_port
            );
        }
    }

    let (sent, received, error_packets, _bytes_sent, bytes_received, latency) = run_udp_test(
        config.test_port,
        config.target_port,
        config.duration,
        with_sleep,
    );

    cleanup_processes(&mut processes);

    result.sent = sent;
    result.received = received;
    result.error_packets = error_packets;
    result.bytes_received = bytes_received;
    result.packet_size_bytes = PACKET_SIZE;

    if sent > 0 {
        result.loss_rate = (sent - received).max(0) as f64 / sent as f64;
        result.throughput = received as f64 / config.duration.as_secs_f64();
    }
    if bytes_received > 0 {
        let seconds = config.duration.as_secs_f64();
        if seconds > 0.0 {
            result.mbps = (bytes_received as f64 * 8.0) / seconds / 1e6;
        }
        result.total_mbytes = bytes_received as f64 / 1e6;
    }

    result.avg_latency_ms = latency.avg_ns / 1e6;
    result.p50_latency_ms = latency.p50_ns / 1e6;
    result.p95_latency_ms = latency.p95_ns / 1e6;
    result.p99_latency_ms = latency.p99_ns / 1e6;
    result.min_latency_ms = latency.min_ns as f64 / 1e6;
    result.max_latency_ms = latency.max_ns as f64 / 1e6;

    if sent == 0 {
        result.error = "No packets sent".to_string();
    } else if with_sleep {
        if error_packets > 0 {
            result.error = format!("Error packets detected: {error_packets}");
        } else if result.loss_rate > MAX_PACKET_LOSS {
            result.error = format!("High packet loss: {:.2}%", result.loss_rate * 100.0);
        } else if received == 0 {
            result.error = "No packets received".to_string();
        } else {
            result.success = true;
        }
    } else if error_packets > 0 {
        result.error = format!("Error packets detected (perf): {error_packets}");
    } else if received == 0 {
        result.error = "No packets received (perf)".to_string();
    } else {
        result.success = true;
    }

    result
}

fn run_udp_test(
    listen_port: u16,
    send_port: u16,
    duration: Duration,
    with_sleep: bool,
) -> (i64, i64, i64, i64, i64, LatencySummary) {
    let sent_count = Arc::new(AtomicI64::new(0));
    let received_count = Arc::new(AtomicI64::new(0));
    let bytes_sent_count = Arc::new(AtomicI64::new(0));
    let bytes_received_count = Arc::new(AtomicI64::new(0));
    let error_count = Arc::new(AtomicI64::new(0));

    let receiver_counts = (
        Arc::clone(&received_count),
        Arc::clone(&bytes_received_count),
        Arc::clone(&error_count),
    );
    let receiver_handle = thread::spawn(move || {
        let mut lat = LatencyAccumulator::default();
        let mut seen_ids = Bitset::default();
        let socket = match UdpSocket::bind(("0.0.0.0", listen_port)) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("Failed to listen on port {listen_port}: {err}");
                return LatencySummary::default();
            }
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
        let deadline = Instant::now() + duration + Duration::from_secs(5);
        let mut buffer = [0u8; 2048];

        while Instant::now() < deadline {
            match socket.recv(&mut buffer) {
                Ok(n) => {
                    if n != PACKET_SIZE {
                        continue;
                    }
                    let packet = parse_packet(&buffer[..PACKET_SIZE]);
                    let Some((id, timestamp, checksum, payload)) = packet else {
                        continue;
                    };

                    if calculate_checksum(id, timestamp, &payload) != checksum {
                        receiver_counts.2.fetch_add(1, Ordering::Relaxed);
                    }

                    let mut count_packet = true;
                    if id > 0 {
                        let idx = id - 1;
                        if seen_ids.test(idx) {
                            count_packet = false;
                        } else {
                            seen_ids.set(idx);
                        }
                    }

                    if count_packet {
                        let now_ns = now_unix_nanos();
                        let latency_ns = (now_ns - timestamp).max(0);
                        lat.observe(latency_ns);
                        receiver_counts.0.fetch_add(1, Ordering::Relaxed);
                        receiver_counts.1.fetch_add(n as i64, Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut
                    {
                        continue;
                    }
                }
            }
        }

        lat.finalize()
    });

    let sender_counts = (Arc::clone(&sent_count), Arc::clone(&bytes_sent_count));
    let sender_handle = thread::spawn(move || {
        let socket = match UdpSocket::bind(("0.0.0.0", 0)) {
            Ok(s) => s,
            Err(err) => {
                eprintln!("Failed to create sender socket: {err}");
                return;
            }
        };
        if let Err(err) = socket.connect(("127.0.0.1", send_port)) {
            eprintln!("Failed to connect to target port {send_port}: {err}");
            return;
        }

        let start = Instant::now();
        let mut packet_id: u32 = 0;
        let mut payload = [0u8; PAYLOAD_SIZE];
        let mut rng = rand::thread_rng();
        let mut consecutive_errors = 0i64;

        while start.elapsed() < duration {
            packet_id = packet_id.wrapping_add(1);
            let timestamp = now_unix_nanos();
            rng.fill_bytes(&mut payload);
            let packet = build_packet(packet_id, timestamp, &payload);

            match socket.send(&packet) {
                Ok(n) => {
                    sender_counts.0.fetch_add(1, Ordering::Relaxed);
                    sender_counts.1.fetch_add(n as i64, Ordering::Relaxed);
                    consecutive_errors = 0;
                }
                Err(_) => {
                    consecutive_errors += 1;
                    if consecutive_errors > 10 {
                        thread::sleep(Duration::from_micros((consecutive_errors as u64) * 10));
                    }
                }
            }

            if with_sleep {
                thread::sleep(Duration::from_micros(1));
            }
        }
    });

    let _ = sender_handle.join();
    let latency = receiver_handle.join().unwrap_or_default();

    let sent = sent_count.load(Ordering::Relaxed);
    let received = received_count.load(Ordering::Relaxed);
    let error_packets = error_count.load(Ordering::Relaxed);
    let bytes_sent = bytes_sent_count.load(Ordering::Relaxed);
    let bytes_received = bytes_received_count.load(Ordering::Relaxed);

    (
        sent,
        received,
        error_packets,
        bytes_sent,
        bytes_received,
        latency,
    )
}

fn start_prismux_process(prismux_binary: &Path, config_path: &Path) -> Result<Child, String> {
    let mut cmd = Command::new(prismux_binary);
    cmd.arg("-c")
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("Failed to start Prismux: {err}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to capture Prismux stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed to capture Prismux stderr".to_string())?;

    let logs = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel::<ProcessEvent>();

    spawn_log_scanner(stdout, "stdout", tx.clone(), Arc::clone(&logs));
    spawn_log_scanner(stderr, "stderr", tx, Arc::clone(&logs));

    let timeout = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            let logs = read_logs(&logs);
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "Prismux did not signal readiness within {timeout:?} for config {}\n--- Logs ---\n{logs}\n------------",
                config_path.display()
            ));
        }

        let wait_for = (deadline - now).min(Duration::from_millis(200));
        match rx.recv_timeout(wait_for) {
            Ok(ProcessEvent::Ready) => return Ok(child),
            Ok(ProcessEvent::Failed(msg)) => {
                let logs = read_logs(&logs);
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "Prismux failed to start for config {}: {msg}\n--- Logs ---\n{logs}\n------------",
                    config_path.display()
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(Some(status)) = child.try_wait() {
                    let logs = read_logs(&logs);
                    return Err(format!(
                        "Prismux exited early with status {status} for config {}\n--- Logs ---\n{logs}\n------------",
                        config_path.display()
                    ));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let logs = read_logs(&logs);
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "Prismux exited with status {status} for config {}\n--- Logs ---\n{logs}\n------------",
                        config_path.display()
                    ));
                }
            }
        }
    }
}

fn spawn_log_scanner<R: Read + Send + 'static>(
    reader: R,
    stream: &'static str,
    tx: mpsc::Sender<ProcessEvent>,
    logs: Arc<Mutex<String>>,
) {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => break,
            };
            if bytes == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();

            if let Ok(mut buf) = logs.lock() {
                buf.push_str(&trimmed);
                buf.push('\n');
            }

            if trimmed.contains("UDPlex started and ready") {
                let _ = tx.send(ProcessEvent::Ready);
            }
            if trimmed.contains("FATAL")
                || trimmed.contains("Failed ")
                || trimmed.contains("Failed:")
            {
                let _ = tx.send(ProcessEvent::Failed(format!("{stream}: {trimmed}")));
            }
        }
    });
}

fn read_logs(logs: &Arc<Mutex<String>>) -> String {
    logs.lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "failed to read logs".to_string())
}

fn cleanup_processes(processes: &mut Vec<Child>) {
    for process in processes {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn get_project_root() -> Result<PathBuf, String> {
    let mut dir = env::current_dir().map_err(|err| format!("Failed to read current dir: {err}"))?;
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join("examples").is_dir() {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    Err("Could not locate project root (Cargo.toml + examples)".to_string())
}

fn resolve_prismux_binary(project_root: &Path) -> Result<PathBuf, String> {
    if let Ok(path) = env::var("CARGO_BIN_EXE_prismux") {
        let binary = PathBuf::from(path);
        if binary.is_file() {
            return Ok(binary);
        }
    }

    let binary_name = if cfg!(windows) {
        "prismux.exe"
    } else {
        "prismux"
    };
    let release_binary = project_root
        .join("target")
        .join("release")
        .join(binary_name);
    if release_binary.is_file() {
        return Ok(release_binary);
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--bin")
        .arg("prismux")
        .current_dir(project_root)
        .env("RUSTFLAGS", "-A dead_code")
        .output()
        .map_err(|err| format!("Failed to build Prismux: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to build Prismux\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    if !release_binary.is_file() {
        return Err(format!(
            "Build finished but binary not found at {}",
            release_binary.display()
        ));
    }
    Ok(release_binary)
}

fn build_packet(id: u32, timestamp: i64, payload: &[u8; PAYLOAD_SIZE]) -> [u8; PACKET_SIZE] {
    let checksum = calculate_checksum(id, timestamp, payload);
    let mut data = [0u8; PACKET_SIZE];
    data[0..4].copy_from_slice(&id.to_le_bytes());
    data[8..16].copy_from_slice(&timestamp.to_le_bytes());
    data[16..48].copy_from_slice(&checksum);
    data[48..PACKET_SIZE].copy_from_slice(payload);
    data
}

fn parse_packet(data: &[u8]) -> Option<(u32, i64, [u8; 32], [u8; PAYLOAD_SIZE])> {
    if data.len() != PACKET_SIZE {
        return None;
    }
    let id = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let timestamp = i64::from_le_bytes(data[8..16].try_into().ok()?);
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&data[16..48]);
    let mut payload = [0u8; PAYLOAD_SIZE];
    payload.copy_from_slice(&data[48..PACKET_SIZE]);
    Some((id, timestamp, checksum, payload))
}

fn calculate_checksum(id: u32, timestamp: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(id.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn now_unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or_default()
}

fn write_json_metrics(
    project_root: &Path,
    results: &[TestResult],
    test_duration: Duration,
) -> Result<(), String> {
    let metrics_dir = project_root.join("metrics");
    fs::create_dir_all(&metrics_dir)
        .map_err(|err| format!("Failed to create metrics dir: {err}"))?;

    let now = Utc::now();
    let timestamp_text = now.to_rfc3339();
    let timestamp_file = now.format("%Y%m%dT%H%M%SZ").to_string();

    let file = MetricsFile {
        repo: getenv_default("GITHUB_REPOSITORY", "local"),
        branch: getenv_default("GITHUB_REF_NAME", &getenv_default("GIT_BRANCH", "local")),
        sha: getenv_default("GITHUB_SHA", &getenv_default("GIT_SHA", "local")),
        run_id: getenv_default("GITHUB_RUN_ID", "0"),
        runner_os: getenv_default("RUNNER_OS", env::consts::OS),
        timestamp: timestamp_text,
        duration_sec: test_duration.as_secs_f64(),
        results: results
            .iter()
            .map(|r| MetricEntry {
                name: r.config_name.clone(),
                sent: r.sent,
                received: r.received,
                error_packets: r.error_packets,
                loss_rate: r.loss_rate,
                throughput_pps: r.throughput,
                mbps: r.mbps,
                total_mbytes: r.total_mbytes,
                packet_size_bytes: r.packet_size_bytes,
                avg_latency_ms: r.avg_latency_ms,
                p50_latency_ms: r.p50_latency_ms,
                p95_latency_ms: r.p95_latency_ms,
                p99_latency_ms: r.p99_latency_ms,
                min_latency_ms: r.min_latency_ms,
                max_latency_ms: r.max_latency_ms,
                success: r.success,
                error: r.error.clone(),
            })
            .collect(),
    };

    let data = serde_json::to_vec_pretty(&file)
        .map_err(|err| format!("Failed to serialize metrics: {err}"))?;
    let latest = metrics_dir.join("latest.json");
    let versioned = metrics_dir.join(format!("{timestamp_file}.json"));

    fs::write(&latest, &data)
        .map_err(|err| format!("Failed to write {}: {err}", latest.display()))?;
    fs::write(&versioned, &data)
        .map_err(|err| format!("Failed to write {}: {err}", versioned.display()))?;

    println!(
        "Metrics written to {} and {}",
        latest.display(),
        versioned.display()
    );
    Ok(())
}

fn getenv_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
