#![no_std]

pub const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JitterEvent {
    pub timestamp_ns: u64,
    pub duration_ns: u64,
    pub cpu_id: u32,
    pub victim_pid: u32,
    pub aggressor_pid: u32,
    pub victim_comm: [u8; TASK_COMM_LEN],
    pub aggressor_comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for JitterEvent {}
