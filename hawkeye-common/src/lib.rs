#![no_std]
#![allow(nonstandard_style)]

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct Event {
    pub pid: u32,
    pub elapsed_ns: u64,
    pub event_type: EventType,
}

#[derive(Copy, Clone)]
pub enum EventType {
    clock_gettime,       // tracepoint:syscalls:sys_enter_clock_gettime
    fsync,               // tracepoint:syscalls:sys_enter_fsync
    fdatasync,           // tracepoint:syscalls:sys_enter_fdatasync
    down_killable,       // kprobe:down_killable
    down_read_killable,  // kprobe:down_read_killable
    down_write_killable, // kprobe:down_write_killable
}

impl Into<u32> for EventType {
    fn into(self) -> u32 {
        match self {
            EventType::clock_gettime => 0,
            EventType::fsync => 1,
            EventType::fdatasync => 2,
            EventType::down_killable => 3,
            EventType::down_read_killable => 4,
            EventType::down_write_killable => 5,
        }
    }
}
