#![no_std]

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub elapsed_ns: u64,
}
