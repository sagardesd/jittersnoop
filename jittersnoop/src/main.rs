use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write as IoWrite};
use std::process::Command as StdCommand;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::collections::{HashMap as StdHashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html,
    },
    routing::get,
    Router,
};
use aya::{
    maps::{HashMap, PerCpuArray, PerCpuValues, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use clap::Parser;
use jittersnoop_common::{JitterEvent, TASK_COMM_LEN};
use log::warn;
use serde::Serialize;
use tokio::signal;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

const HISTORY_CAPACITY: usize = 100;
const MINUTES_24H: usize = 1440;
const WORST_EVENTS_CAP: usize = 50;
const HIST_BOUNDS: [u64; 19] = [
    1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000,
    1_000_000, 2_000_000, 5_000_000, 10_000_000, 20_000_000, 50_000_000,
    100_000_000, 200_000_000, 500_000_000, 1_000_000_000,
];
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
static EBPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("EBPF_OBJ")));

// Json event for the web dashboard
#[derive(Clone, Serialize)]
struct JitterEventJson {
    timestamp_ns: u64,
    duration_ns: u64,
    cpu_id: u32,
    victim_pid: u32,
    aggressor_pid: u32,
    victim_comm: String,
    aggressor_comm: String,
}

impl From<&JitterEvent> for JitterEventJson {
    fn from(e: &JitterEvent) -> Self {
        Self {
            timestamp_ns: e.timestamp_ns,
            duration_ns: e.duration_ns,
            cpu_id: e.cpu_id,
            victim_pid: e.victim_pid,
            aggressor_pid: e.aggressor_pid,
            victim_comm: comm_to_string(&e.victim_comm),
            aggressor_comm: comm_to_string(&e.aggressor_comm),
        }
    }
}

// Rolling buffer
struct RollingBuffer {
    events: Vec<JitterEvent>,
    head: usize,
    count: usize,
}

impl RollingBuffer {
    fn new() -> Self {
        Self {
            events: vec![
                JitterEvent {
                    timestamp_ns: 0,
                    duration_ns: 0,
                    cpu_id: 0,
                    victim_pid: 0,
                    aggressor_pid: 0,
                    victim_comm: [0u8; TASK_COMM_LEN],
                    aggressor_comm: [0u8; TASK_COMM_LEN],
                };
                HISTORY_CAPACITY
            ],
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: JitterEvent) {
        self.events[self.head] = event;
        self.head = (self.head + 1) % HISTORY_CAPACITY;
        if self.count < HISTORY_CAPACITY {
            self.count += 1;
        }
    }

    fn recent_json(&self) -> Vec<JitterEventJson> {
        let start = if self.count < HISTORY_CAPACITY {
            0
        } else {
            self.head
        };
        (0..self.count)
            .map(|i| {
                let idx = (start + i) % HISTORY_CAPACITY;
                JitterEventJson::from(&self.events[idx])
            })
            .collect()
    }
}

// ─── 24-hour history store ───

fn hist_bucket_index(ns: u64) -> usize {
    HIST_BOUNDS.iter().position(|&b| ns < b).unwrap_or(HIST_BOUNDS.len())
}

fn severity_index(ns: u64) -> usize {
    if ns < 10_000 { 0 }
    else if ns < 100_000 { 1 }
    else if ns < 1_000_000 { 2 }
    else { 3 }
}

struct MinuteBucket {
    minute_ts: u64,
    count: u32,
    max_ns: u64,
    min_ns: u64,
    sum_ns: u64,
    sev: [u32; 4],
    histogram: [u32; 20],
    aggressors: StdHashMap<String, (u32, u64)>,
    cpus: StdHashMap<u32, (u32, u64)>,
}

impl MinuteBucket {
    fn new(minute_ts: u64) -> Self {
        Self {
            minute_ts,
            count: 0,
            max_ns: 0,
            min_ns: u64::MAX,
            sum_ns: 0,
            sev: [0; 4],
            histogram: [0; 20],
            aggressors: StdHashMap::new(),
            cpus: StdHashMap::new(),
        }
    }

    fn record(&mut self, duration_ns: u64, aggressor_comm: &str, cpu_id: u32) {
        self.count += 1;
        if duration_ns > self.max_ns { self.max_ns = duration_ns; }
        if duration_ns < self.min_ns { self.min_ns = duration_ns; }
        self.sum_ns += duration_ns;
        self.sev[severity_index(duration_ns)] += 1;
        self.histogram[hist_bucket_index(duration_ns)] += 1;
        let entry = self.aggressors.entry(aggressor_comm.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += duration_ns;
        let cpu_entry = self.cpus.entry(cpu_id).or_insert((0, 0));
        cpu_entry.0 += 1;
        if duration_ns > cpu_entry.1 { cpu_entry.1 = duration_ns; }
    }
}

struct WorstEvent {
    wall_time_ms: u64,
    duration_ns: u64,
    cpu_id: u32,
    victim_pid: u32,
    aggressor_pid: u32,
    victim_comm: String,
    aggressor_comm: String,
}

struct History24hStore {
    buckets: VecDeque<MinuteBucket>,
    worst: Vec<WorstEvent>,
}

impl History24hStore {
    fn new() -> Self {
        Self {
            buckets: VecDeque::with_capacity(MINUTES_24H + 1),
            worst: Vec::new(),
        }
    }

    fn record(&mut self, event: &JitterEvent, wall_time_ms: u64) {
        let minute_ts = wall_time_ms / 60_000 * 60;
        let aggressor_comm = comm_to_string(&event.aggressor_comm);

        let need_new = self.buckets.back().map_or(true, |b| b.minute_ts != minute_ts);
        if need_new {
            self.buckets.push_back(MinuteBucket::new(minute_ts));
        }
        self.buckets.back_mut().unwrap().record(event.duration_ns, &aggressor_comm, event.cpu_id);

        let cutoff = minute_ts.saturating_sub(24 * 3600);
        while self.buckets.front().map_or(false, |b| b.minute_ts < cutoff) {
            self.buckets.pop_front();
        }

        if self.worst.len() < WORST_EVENTS_CAP
            || event.duration_ns > self.worst.last().map_or(0, |w| w.duration_ns)
        {
            let victim_comm = comm_to_string(&event.victim_comm);
            self.worst.push(WorstEvent {
                wall_time_ms,
                duration_ns: event.duration_ns,
                cpu_id: event.cpu_id,
                victim_pid: event.victim_pid,
                aggressor_pid: event.aggressor_pid,
                victim_comm,
                aggressor_comm,
            });
            self.worst.sort_by(|a, b| b.duration_ns.cmp(&a.duration_ns));
            self.worst.truncate(WORST_EVENTS_CAP);
        }

        let cutoff_ms = wall_time_ms.saturating_sub(24 * 3600 * 1000);
        self.worst.retain(|w| w.wall_time_ms >= cutoff_ms);
    }
}

#[derive(Serialize)]
struct MinuteBucketJson {
    minute_ts: u64,
    count: u32,
    max_ns: u64,
    min_ns: u64,
    avg_ns: u64,
    sev: [u32; 4],
}

#[derive(Serialize)]
struct WorstEventJson24h {
    wall_time_ms: u64,
    duration_ns: u64,
    cpu_id: u32,
    victim_pid: u32,
    aggressor_pid: u32,
    victim_comm: String,
    aggressor_comm: String,
}

#[derive(Serialize)]
struct AggressorSummaryJson {
    comm: String,
    count: u32,
    total_ns: u64,
}

#[derive(Serialize)]
struct Summary24hJson {
    total_events: u64,
    max_ns: u64,
    max_wall_time_ms: u64,
    max_aggressor: String,
    max_victim: String,
    max_cpu: u32,
    approx_p50_ns: u64,
    approx_p99_ns: u64,
    sev: [u64; 4],
    window_start_ms: u64,
    window_end_ms: u64,
}

#[derive(Serialize)]
struct CpuMinuteJson {
    minute_ts: u64,
    cpu_id: u32,
    count: u32,
    max_ns: u64,
}

#[derive(Serialize)]
struct History24hJson {
    minutes: Vec<MinuteBucketJson>,
    worst_events: Vec<WorstEventJson24h>,
    top_aggressors: Vec<AggressorSummaryJson>,
    summary: Summary24hJson,
    histogram: Vec<u32>,
    cpu_heatmap: Vec<CpuMinuteJson>,
}

fn approx_percentile(histogram: &[u32], total: u64, p: f64) -> u64 {
    if total == 0 { return 0; }
    let target = (total as f64 * p) as u64;
    let mut cumulative: u64 = 0;
    for (i, &count) in histogram.iter().enumerate() {
        cumulative += count as u64;
        if cumulative >= target {
            return if i < HIST_BOUNDS.len() { HIST_BOUNDS[i] } else { *HIST_BOUNDS.last().unwrap() };
        }
    }
    *HIST_BOUNDS.last().unwrap_or(&0)
}

#[derive(Parser, Debug)]
#[command(
    name = "jittersnoop",
    version,
    about = "Zero-overhead scheduling jitter flight recorder for isolated cores.\n\n\
             Quick start:  sudo jittersnoop --demo"
)]
struct Args {
    /// Run a self-contained demo: spawns a victim + aggressor on a core and monitors it
    #[arg(long)]
    demo: bool,

    /// Comma-separated list of CPU core IDs to monitor (e.g. "4,5,6")
    #[arg(long, value_delimiter = ',')]
    cores: Vec<u32>,

    /// Only report jitter against these PIDs (your pinned processes). Omit to monitor all.
    #[arg(long, value_delimiter = ',')]
    pid: Vec<u32>,

    /// Jitter threshold in nanoseconds
    #[arg(long, default_value_t = 1_000)]
    threshold_ns: u64,

    /// Port for the web dashboard
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Log events to a CSV file (e.g. --log jitter.csv)
    #[arg(long)]
    log: Option<String>,
}

// Shared app state
#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<JitterEventJson>,
    history: Arc<Mutex<RollingBuffer>>,
    history24h: Arc<Mutex<History24hStore>>,
    start_time_ms: u64,
}

// Helpers
fn comm_to_string(comm: &[u8; TASK_COMM_LEN]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

// Web Handlers
async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let rx = state.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).ok()?;
            Some(Ok(Event::default().data(json)))
        }
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn history_handler(
    State(state): State<AppState>,
) -> axum::Json<Vec<JitterEventJson>> {
    let hist = state.history.lock().unwrap();
    axum::Json(hist.recent_json())
}

async fn history24h_handler(
    State(state): State<AppState>,
) -> axum::Json<History24hJson> {
    let store = state.history24h.lock().unwrap();

    let minutes: Vec<MinuteBucketJson> = store.buckets.iter().map(|b| MinuteBucketJson {
        minute_ts: b.minute_ts,
        count: b.count,
        max_ns: b.max_ns,
        min_ns: if b.min_ns == u64::MAX { 0 } else { b.min_ns },
        avg_ns: if b.count > 0 { b.sum_ns / b.count as u64 } else { 0 },
        sev: b.sev,
    }).collect();

    let mut histogram = vec![0u32; 20];
    let mut total_events: u64 = 0;
    let mut global_max: u64 = 0;
    let mut sev_totals = [0u64; 4];
    let mut agg_map: StdHashMap<String, (u32, u64)> = StdHashMap::new();

    for b in &store.buckets {
        total_events += b.count as u64;
        if b.max_ns > global_max { global_max = b.max_ns; }
        for i in 0..4 { sev_totals[i] += b.sev[i] as u64; }
        for i in 0..20 { histogram[i] += b.histogram[i]; }
        for (comm, &(count, total_ns)) in &b.aggressors {
            let entry = agg_map.entry(comm.clone()).or_insert((0, 0));
            entry.0 += count;
            entry.1 += total_ns;
        }
    }

    let approx_p50_ns = approx_percentile(&histogram, total_events, 0.50);
    let approx_p99_ns = approx_percentile(&histogram, total_events, 0.99);

    let mut top_aggressors: Vec<AggressorSummaryJson> = agg_map.into_iter()
        .map(|(comm, (count, total_ns))| AggressorSummaryJson { comm, count, total_ns })
        .collect();
    top_aggressors.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
    top_aggressors.truncate(20);

    let worst_events: Vec<WorstEventJson24h> = store.worst.iter().map(|w| WorstEventJson24h {
        wall_time_ms: w.wall_time_ms,
        duration_ns: w.duration_ns,
        cpu_id: w.cpu_id,
        victim_pid: w.victim_pid,
        aggressor_pid: w.aggressor_pid,
        victim_comm: w.victim_comm.clone(),
        aggressor_comm: w.aggressor_comm.clone(),
    }).collect();

    let (max_wall_time_ms, max_aggressor, max_victim, max_cpu) = store.worst.first()
        .map(|w| (w.wall_time_ms, w.aggressor_comm.clone(), w.victim_comm.clone(), w.cpu_id))
        .unwrap_or((0, String::new(), String::new(), 0));

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;

    let summary = Summary24hJson {
        total_events,
        max_ns: global_max,
        max_wall_time_ms,
        max_aggressor,
        max_victim,
        max_cpu,
        approx_p50_ns,
        approx_p99_ns,
        sev: sev_totals,
        window_start_ms: store.buckets.front().map_or(now_ms, |b| b.minute_ts * 1000),
        window_end_ms: now_ms,
    };

    let mut cpu_heatmap: Vec<CpuMinuteJson> = Vec::new();
    for b in &store.buckets {
        for (&cpu_id, &(count, max_ns)) in &b.cpus {
            cpu_heatmap.push(CpuMinuteJson {
                minute_ts: b.minute_ts,
                cpu_id,
                count,
                max_ns,
            });
        }
    }

    axum::Json(History24hJson {
        minutes,
        worst_events,
        top_aggressors,
        summary,
        histogram,
        cpu_heatmap,
    })
}

async fn status_handler(
    State(state): State<AppState>,
) -> axum::Json<serde_json::Value> {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    axum::Json(serde_json::json!({
        "start_time_ms": state.start_time_ms,
        "uptime_ms": now_ms.saturating_sub(state.start_time_ms),
    }))
}

// Demo mode
struct DemoProcesses {
    victim: std::process::Child,
    aggressors: Vec<std::process::Child>,
    victim_pid: u32,
    _core: u32,
}

fn pick_demo_core() -> u32 {
    let nr = aya::util::nr_cpus()
        .map(|n| n as u32)
        .unwrap_or(4);
    // Use the last core — least likely to be busy with system services
    nr.saturating_sub(1).max(1)
}

fn spawn_demo(core: u32) -> Result<DemoProcesses> {
    let victim = StdCommand::new("taskset")
        .args([
            "-c",
            &core.to_string(),
            "bash",
            "-c",
            "exec -a jsnoop-victim bash -c 'while true; do :; done'",
        ])
        .spawn()
        .context("failed to spawn victim process")?;

    let victim_pid = victim.id();

    let aggressor_cmds = [
        "exec -a jsnoop-aggressor bash -c 'while true; do dd if=/dev/urandom of=/dev/null bs=64K count=8 2>/dev/null; done'",
        "exec -a jsnoop-malloc bash -c 'while true; do head -c 1M /dev/urandom | sha256sum > /dev/null; done'",
        "exec -a jsnoop-io bash -c 'while true; do sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; sleep 0.01; done'",
    ];

    let mut aggressors = Vec::new();
    for cmd in &aggressor_cmds {
        let child = StdCommand::new("taskset")
            .args(["-c", &core.to_string(), "bash", "-c", cmd])
            .spawn()
            .context("failed to spawn aggressor process")?;
        aggressors.push(child);
    }

    Ok(DemoProcesses {
        victim,
        aggressors,
        victim_pid,
        _core: core,
    })
}

// Main
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let mut args = Args::parse();

    // Demo mode: auto-configure everything
    let mut demo_procs: Option<DemoProcesses> = None;
    if args.demo {
        let core = pick_demo_core();
        let procs = spawn_demo(core)?;
        let vpid = procs.victim_pid;
        args.cores = vec![core];
        args.pid = vec![vpid];
        println!();
        println!("  Demo mode: victim PID {} + 3 aggressors on core {}", vpid, core);
        demo_procs = Some(procs);
        // Give processes a moment to start
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    if args.cores.is_empty() {
        anyhow::bail!("specify --cores or use --demo for a quick start");
    }

    // Load embedded eBPF
    let bpf: &'static mut Ebpf = Box::leak(Box::new(
        Ebpf::load(EBPF_BYTES).context("failed to load embedded eBPF program — are you running as root?")?,
    ));

    // Populate MONITORED_CORES
    {
        let mut monitored: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("MONITORED_CORES")
                .context("MONITORED_CORES map not found")?,
        )?;
        for &core in &args.cores {
            monitored.insert(core, 1, 0)?;
        }
    }

    // Set threshold
    {
        let mut threshold_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            bpf.map_mut("JITTER_THRESHOLD")
                .context("JITTER_THRESHOLD map not found")?,
        )?;
        let nr_cpus = aya::util::nr_cpus()
            .map_err(|(msg, io_err)| anyhow::anyhow!("{}: {}", msg, io_err))?;
        let values = PerCpuValues::try_from(vec![args.threshold_ns; nr_cpus])?;
        threshold_map.set(0, values, 0)?;
    }

    // Populate MONITORED_PIDS
    {
        let mut pids: HashMap<_, u32, u8> = HashMap::try_from(
            bpf.map_mut("MONITORED_PIDS")
                .context("MONITORED_PIDS map not found")?,
        )?;
        if args.pid.is_empty() {
            pids.insert(0, 1, 0)?;
        } else {
            for &p in &args.pid {
                pids.insert(p, 1, 0)?;
            }
        }
    }

    // Attach tracepoint
    let program: &mut TracePoint = bpf
        .program_mut("jittersnoop")
        .context("tracepoint program not found in eBPF object")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_switch")?;

    // Broadcast channel for SSE
    let (tx, _) = broadcast::channel::<JitterEventJson>(4096);
    let history = Arc::new(Mutex::new(RollingBuffer::new()));
    let history24h = Arc::new(Mutex::new(History24hStore::new()));
    let running = Arc::new(AtomicBool::new(true));

    let start_time_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    let state = AppState {
        tx: tx.clone(),
        history: history.clone(),
        history24h: history24h.clone(),
        start_time_ms,
    };

    // Web server
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/events", get(sse_handler))
        .route("/history", get(history_handler))
        .route("/api/history24h", get(history24h_handler))
        .route("/api/status", get(status_handler))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!();
    println!("  +-------------------------------------------------------------------+");
    println!("  |  JitterSnoop -- Scheduling Jitter Flight Recorder                 |");
    println!("  +-------------------------------------------------------------------+");
    println!();
    println!("  Cores:      {:?}", args.cores);
    println!("  Threshold:  {} ns", args.threshold_ns);
    if args.pid.is_empty() {
        println!("  Filter:     all processes");
    } else {
        println!("  Filter:     PIDs {:?}", args.pid);
    }
    println!("  Dashboard:  http://localhost:{}", args.port);
    println!();
    println!("  Open the URL above in your browser. Press Ctrl-C to stop.");
    println!();

    // CSV logger (buffered, flushed every batch)
    let csv_writer: Option<Mutex<BufWriter<File>>> = if let Some(ref path) = args.log {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .context("failed to open log file")?;
        let mut w = BufWriter::new(file);
        if std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true) {
            writeln!(w, "timestamp_ns,duration_ns,cpu_id,victim_pid,aggressor_pid,victim_comm,aggressor_comm")?;
        }
        println!("  Logging:    {}", path);
        Some(Mutex::new(w))
    } else {
        None
    };
    let csv_writer = Arc::new(csv_writer);

    // Ring buffer poller
    let mut poll_ring = RingBuf::try_from(
        bpf.map_mut("EVENTS")
            .context("EVENTS ring buffer not found")?,
    )?;

    let poll_tx = tx.clone();
    let poll_history = history.clone();
    let poll_history24h = history24h.clone();
    let poll_running = running.clone();
    let poll_csv = csv_writer.clone();

    let poll_handle = tokio::task::spawn_blocking(move || {
        while poll_running.load(Ordering::Relaxed) {
            let mut batch = false;
            while let Some(item) = poll_ring.next() {
                let data = item.as_ref();
                if data.len() < core::mem::size_of::<JitterEvent>() {
                    warn!("undersized ring buffer entry, skipping");
                    continue;
                }
                let event: JitterEvent =
                    unsafe { core::ptr::read_unaligned(data.as_ptr() as *const JitterEvent) };

                let json_event = JitterEventJson::from(&event);
                let _ = poll_tx.send(json_event);

                if let Ok(mut h) = poll_history.lock() {
                    h.push(event);
                }

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                if let Ok(mut h) = poll_history24h.lock() {
                    h.record(&event, now_ms);
                }

                if let Some(ref csv) = *poll_csv {
                    if let Ok(mut w) = csv.lock() {
                        let _ = writeln!(w, "{},{},{},{},{},{},{}",
                            event.timestamp_ns, event.duration_ns, event.cpu_id,
                            event.victim_pid, event.aggressor_pid,
                            comm_to_string(&event.victim_comm),
                            comm_to_string(&event.aggressor_comm),
                        );
                        batch = true;
                    }
                }
            }
            if batch {
                if let Some(ref csv) = *poll_csv {
                    if let Ok(mut w) = csv.lock() {
                        let _ = w.flush();
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });

    // Run web server and wait for Ctrl-C
    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                eprintln!("  Web server error: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            println!("\n  Shutting down...");
        }
    }

    running.store(false, Ordering::Relaxed);
    poll_handle.abort();

    // Cleanup demo processes
    if let Some(mut procs) = demo_procs {
        let _ = procs.victim.kill();
        let _ = procs.victim.wait();
        for ag in &mut procs.aggressors {
            let _ = ag.kill();
            let _ = ag.wait();
        }
        println!("  Demo processes cleaned up.");
    }

    let hist = history.lock().unwrap();
    if hist.count > 0 {
        println!("  Captured {} events in rolling buffer.", hist.count);
    }

    Ok(())
}
