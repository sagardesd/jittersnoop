#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};
use jittersnoop_common::{JitterEvent, TASK_COMM_LEN};

#[map]
static MONITORED_CORES: HashMap<u32, u8> = HashMap::with_max_entries(128, 0);

#[map]
static MONITORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static START_TS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static VICTIM_PID: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static VICTIM_COMM: PerCpuArray<[u8; TASK_COMM_LEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static JITTER_THRESHOLD: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Tracepoint field offsets (after the 8-byte tracepoint header):
//   +0:  prev_comm[16]   +16: prev_pid (i32)   +20: prev_prio (i32)
//   +24: prev_state (i64) +32: next_comm[16]   +48: next_pid (i32)
const PREV_COMM_OFFSET: usize = 8;
const PREV_PID_OFFSET: usize = 24;
const _NEXT_COMM_OFFSET: usize = 40;
const NEXT_PID_OFFSET: usize = 56;

#[tracepoint]
pub fn jittersnoop(ctx: TracePointContext) -> u32 {
    match try_jittersnoop(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_jittersnoop(ctx: &TracePointContext) -> Result<(), i64> {
    let cpu = unsafe { bpf_get_smp_processor_id() };

    if unsafe { MONITORED_CORES.get(&cpu) }.is_none() {
        return Ok(());
    }

    let now = unsafe { bpf_ktime_get_ns() };

    let prev_pid: i32 = unsafe { ctx.read_at(PREV_PID_OFFSET).map_err(|_| 1i64)? };
    let next_pid: i32 = unsafe { ctx.read_at(NEXT_PID_OFFSET).map_err(|_| 1i64)? };

    let prev_comm: [u8; TASK_COMM_LEN] = unsafe {
        bpf_probe_read_kernel((ctx.as_ptr() as *const u8).add(PREV_COMM_OFFSET) as *const _)
            .map_err(|_| 1i64)?
    };

    let start_ts = START_TS.get_ptr_mut(0).ok_or(1i64)?;
    let saved_pid = VICTIM_PID.get_ptr_mut(0).ok_or(1i64)?;
    let saved_comm = VICTIM_COMM.get_ptr_mut(0).ok_or(1i64)?;

    let recorded_ts = unsafe { *start_ts };
    let recorded_pid = unsafe { *saved_pid };

    if recorded_ts > 0 && (next_pid as u32) == recorded_pid {
        let duration = now.saturating_sub(recorded_ts);
        let threshold = JITTER_THRESHOLD.get(0).copied().unwrap_or(1_000);

        let pid_match = unsafe { MONITORED_PIDS.get(&recorded_pid).is_some() };
        let no_pid_filter = unsafe { MONITORED_PIDS.get(&0).is_some() };
        if duration >= threshold && (no_pid_filter || pid_match) {
            if let Some(mut buf) = EVENTS.reserve::<JitterEvent>(0) {
                let event = unsafe { &mut *buf.as_mut_ptr() };
                event.timestamp_ns = now;
                event.duration_ns = duration;
                event.cpu_id = cpu;
                event.victim_pid = recorded_pid;
                event.aggressor_pid = prev_pid as u32;
                event.victim_comm = unsafe { *saved_comm };
                event.aggressor_comm = prev_comm;
                buf.submit(0);
            }
        }
    }

    unsafe {
        *start_ts = now;
        *saved_pid = prev_pid as u32;
        *saved_comm = prev_comm;
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
